# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""The recreate-fixtures sub-command recreates the entire test fixture data.

The test suite should be sufficiently modular to still run without errors after running this command.
"""

import json
import os
import shutil
from collections.abc import Sequence
from datetime import datetime, timezone as tz
from pathlib import Path
from typing import Any, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    KeySerializationEncryption,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from django.conf import settings

from freezegun import freeze_time

from devscripts import config
from django_ca import ca_settings
from django_ca.key_backends import key_backends
from django_ca.key_backends.storages import CreatePrivateKeyOptions, UsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import profiles
from django_ca.pydantic.extensions import (
    EXTENSION_MODELS,
    AuthorityInformationAccessModel,
    CRLDistributionPointsModel,
    ExtensionModel,
    UnrecognizedExtensionModel,
)
from django_ca.tests.base.typehints import CertFixtureData, OcspFixtureData
from django_ca.typehints import ParsableKeyType
from django_ca.utils import bytes_to_hex, parse_serialized_name_attributes, serialize_name

DEFAULT_KEY_SIZE = 2048  # Size for private keys
TIMEFORMAT = "%Y-%m-%d %H:%M:%S"


class CertificateEncoder(json.JSONEncoder):
    """Minor class to encode certificate data into json."""

    def default(self, o: Any) -> Any:  # Any/Any matches base class typehints
        if isinstance(o, hashes.HashAlgorithm):
            return o.name
        if isinstance(o, Path):
            return str(o)
        if isinstance(o, x509.Extensions):
            return list(o)
        if isinstance(o, x509.Extension):
            if isinstance(o.value, x509.UnrecognizedExtension):
                model_class: type[ExtensionModel[Any]] = UnrecognizedExtensionModel
            else:
                model_class = EXTENSION_MODELS[o.oid]
            model = model_class.model_validate(o, context={"validate_required_critical": False})
            return model.model_dump(mode="json")
        return json.JSONEncoder.default(self, o)


def _create_key(path: Path, key_type: ParsableKeyType) -> CertificateIssuerPrivateKeyTypes:
    if key_type == "RSA":
        key: CertificateIssuerPrivateKeyTypes = rsa.generate_private_key(
            public_exponent=65537, key_size=DEFAULT_KEY_SIZE
        )
    elif key_type == "DSA":
        key = dsa.generate_private_key(2048)
    elif key_type == "EC":
        key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == "Ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == "Ed448":
        key = ed448.Ed448PrivateKey.generate()
    else:
        raise ValueError(f"Unknown key type: {key_type}")

    encoded = key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(encoded)
    return key


def _create_csr(
    key_path: Path, path: Path, subject: x509.Name, key_type: ParsableKeyType = "RSA"
) -> x509.CertificateSigningRequest:
    key = _create_key(key_path, key_type)
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    if isinstance(key, (ed448.Ed448PrivateKey, ed25519.Ed25519PrivateKey)):
        csr = csr_builder.sign(key, algorithm=None)
    else:
        csr = csr_builder.sign(key, algorithm=hashes.SHA256())

    with open(path, "wb") as stream:
        stream.write(csr.public_bytes(Encoding.DER))
    return csr


def _update_cert_data(cert: Union[CertificateAuthority, Certificate], data: dict[str, Any]) -> None:
    data["serial"] = cert.serial
    data["sha256"] = cert.get_fingerprint(hashes.SHA256())
    data["sha512"] = cert.get_fingerprint(hashes.SHA512())
    data["extensions"] = cert.pub.loaded.extensions


def _write_ca(
    dest: Path, ca: CertificateAuthority, cert_data: CertFixtureData, password: Optional[bytes] = None
) -> None:
    # Encode private key
    if password is None:
        encryption: KeySerializationEncryption = NoEncryption()
    else:
        encryption = BestAvailableEncryption(password)
    key_backend_options = UsePrivateKeyOptions(password=password)
    key_der = ca.key_backend.get_key(ca, key_backend_options).private_bytes(  # type: ignore[attr-defined]
        encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
    )

    # write files to dest
    with open(dest / cert_data["key_filename"], "wb") as stream:
        stream.write(key_der)
    with open(dest / cert_data["pub_filename"], "wb") as stream:
        stream.write(ca.pub.der)

    # These keys are only present in CAs:
    cert_data["sign_authority_information_access"] = AuthorityInformationAccessModel.model_validate(
        ca.sign_authority_information_access
    ).model_dump(mode="json")
    cert_data["sign_crl_distribution_points"] = CRLDistributionPointsModel.model_validate(
        ca.sign_crl_distribution_points
    ).model_dump(mode="json")

    # Update common data for CAs and certs
    _update_cert_data(ca, cert_data)


def _copy_cert(dest: Path, cert: Certificate, data: CertFixtureData, key_path: Path, csr_path: Path) -> None:
    csr_dest = dest / data["csr_filename"]

    shutil.copy(key_path, dest / data["key_filename"])
    shutil.copy(csr_path, csr_dest)
    with open(dest / data["pub_filename"], "wb") as stream:
        stream.write(cert.pub.der)

    data["subject"] = serialize_name(cert.subject)
    data["parsed_cert"] = cert

    _update_cert_data(cert, data)


def _update_contrib(
    parsed: x509.Certificate,
    data: dict[str, Any],
    cert: Union[Certificate, CertificateAuthority],
    name: str,
    filename: str,
) -> None:
    cert_data = {
        "name": name,
        "cn": cert.cn,
        "cat": "sphinx-contrib",
        "extensions": parsed.extensions,
        "pub_filename": filename,
        "key_filename": False,
        "csr_filename": False,
        "serial": cert.serial,
        "subject": serialize_name(cert.subject),
        "md5": cert.get_fingerprint(hashes.MD5()),
        "sha1": cert.get_fingerprint(hashes.SHA1()),
        "sha256": cert.get_fingerprint(hashes.SHA256()),
        "sha512": cert.get_fingerprint(hashes.SHA512()),
    }

    data[name] = cert_data


def _generate_contrib_files(data: dict[str, dict[str, Any]]) -> None:
    files_dir = config.DOCS_DIR / "source" / "_files"
    for filename in (files_dir / "ca").iterdir():
        name = filename.stem

        with open(filename, "rb") as stream:
            pem = stream.read()

        parsed = x509.load_pem_x509_certificate(pem)
        ca = CertificateAuthority(name=name)
        ca.update_certificate(parsed)

        _update_contrib(parsed, data, ca, name, filename.name)
        data[name]["type"] = "ca"
        data[name]["path_length"] = ca.path_length

        public_key = parsed.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            data[name]["key_type"] = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            data[name]["key_type"] = "EC"
        else:
            raise ValueError(f"Unknown type of Public key encountered: {public_key}")

    for filename in (files_dir / "cert").iterdir():
        name = filename.stem

        contrib_ca = None
        if name in data:
            contrib_ca = name

        name = f"{name}-cert"

        with open(filename, "rb") as stream:
            pem = stream.read()

        parsed = x509.load_pem_x509_certificate(pem)
        cert = Certificate()
        cert.update_certificate(parsed)
        _update_contrib(parsed, data, cert, name, filename.name)
        data[name]["type"] = "cert"

        if contrib_ca:
            data[name]["ca"] = contrib_ca

        public_key = parsed.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            data[name]["key_type"] = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            data[name]["key_type"] = "EC"
        else:
            raise ValueError(f"Unknown type of Public key encountered: {public_key}")


def create_cas(dest: Path, now: datetime, delay: bool, data: CertFixtureData) -> list[CertificateAuthority]:
    """Create CAs."""
    ca_names = [v["name"] for k, v in data.items() if v.get("type") == "ca"]

    # sort ca_names so that any children are created last
    ca_names = sorted(ca_names, key=lambda n: data[n].get("parent", ""))
    ca_instances = []

    for name in ca_names:
        # Get some data from the parent, if present
        parent: Optional[CertificateAuthority] = None
        use_parent_private_key_options = None
        parent_name = data[name].get("parent")
        if parent_name:
            parent = CertificateAuthority.objects.get(name=parent_name)
            use_parent_private_key_options = UsePrivateKeyOptions(password=data[parent_name].get("password"))

        freeze_now = now
        if delay:
            freeze_now += data[name]["delta"]

        key_backend = key_backends[ca_settings.CA_DEFAULT_KEY_BACKEND]
        key_backend_options = CreatePrivateKeyOptions(
            key_type=data[name]["key_type"],
            password=data[name].get("password"),
            path="ca",
            key_size=data[name].get("key_size"),
        )
        with freeze_time(freeze_now):
            ca = CertificateAuthority.objects.init(
                data[name]["name"],
                key_backend,
                key_backend_options,
                subject=x509.Name(parse_serialized_name_attributes(data[name]["subject"])),
                expires=datetime.now(tz=tz.utc) + data[name]["expires"],
                key_type=data[name]["key_type"],
                algorithm=data[name].get("algorithm"),
                path_length=data[name]["path_length"],
                parent=parent,
                use_parent_private_key_options=use_parent_private_key_options,
            )

        ca_instances.append(ca)
        _write_ca(dest, ca, data[name], password=data[name].get("password"))

    # add parent/child relationships
    data["root"]["children"] = [[data["child"]["name"], data["child"]["serial"]]]
    return ca_instances


def create_certs(
    dest: Path, cas: Sequence[CertificateAuthority], now: datetime, delay: bool, data: dict[str, Any]
) -> None:
    """Create regular certificates."""
    # let's create a standard certificate for every CA
    for ca in cas:
        name = f"{ca.name}-cert"
        key_path = Path(os.path.join(settings.CA_DIR, f"{name}.key"))
        csr_path = Path(os.path.join(settings.CA_DIR, f"{name}.csr"))
        csr_subject = x509.Name(parse_serialized_name_attributes(data[name]["csr_subject"]))
        csr = _create_csr(
            key_path,
            csr_path,
            subject=csr_subject,
            key_type=data[name]["key_type"],
        )

        freeze_now = now
        if delay:
            freeze_now += data[name]["delta"]

        pwd = data[data[name]["ca"]].get("password")
        with freeze_time(freeze_now):
            cert = Certificate.objects.create_cert(
                ca=ca,
                key_backend_options=UsePrivateKeyOptions(password=pwd),
                csr=csr,
                profile=profiles["server"],
                expires=data[name]["expires"],
                algorithm=data[name]["algorithm"],
                subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, data[name]["cn"])]),
                extensions=data[name].get("extensions", {}).values(),
            )
        _copy_cert(dest, cert, data[name], key_path, csr_path)

    # create a cert for every profile
    for profile in ca_settings.CA_PROFILES:
        name = f"profile-{profile}"
        ca = CertificateAuthority.objects.get(name=data[name]["ca"])

        key_path = Path(os.path.join(settings.CA_DIR, f"{name}.key"))
        csr_path = Path(os.path.join(settings.CA_DIR, f"{name}.csr"))
        csr_subject = x509.Name(parse_serialized_name_attributes(data[name]["csr_subject"]))
        csr = _create_csr(
            key_path,
            csr_path,
            subject=csr_subject,
            key_type=data[name]["key_type"],
        )

        freeze_now = now
        if delay:
            freeze_now += data[name]["delta"]

        pwd = data[ca.name].get("password")
        with freeze_time(freeze_now):
            cert = Certificate.objects.create_cert(
                ca=ca,
                key_backend_options=UsePrivateKeyOptions(password=pwd),
                csr=csr,
                profile=profiles[profile],
                algorithm=data[name]["algorithm"],
                expires=data[name]["expires"],
                subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, data[name]["cn"])]),
                extensions=data[name].get("extensions", {}).values(),
            )

        data[name]["profile"] = profile
        _copy_cert(dest, cert, data[name], key_path, csr_path)


def create_special_certs(  # noqa: PLR0915
    dest: Path, now: datetime, delay: bool, data: CertFixtureData
) -> None:
    """Create special-interest certificates (edge cases etc.)."""
    # create a cert with absolutely no extensions
    name = "no-extensions"
    ca = CertificateAuthority.objects.get(name=data[name]["ca"])
    key_path = Path(os.path.join(settings.CA_DIR, f"{name}.key"))
    csr_path = Path(os.path.join(settings.CA_DIR, f"{name}.csr"))
    csr_subject = x509.Name(parse_serialized_name_attributes(data[name]["csr_subject"]))
    csr = _create_csr(key_path, csr_path, subject=csr_subject)

    freeze_now = now
    if delay:
        freeze_now += data[name]["delta"]
    with freeze_time(freeze_now):
        no_ext_now = datetime.now(tz=tz.utc).replace(tzinfo=None)
        pwd = data[ca.name].get("password")
        subject = x509.Name(parse_serialized_name_attributes(data[name]["subject"]))

        builder = x509.CertificateBuilder()
        builder = builder.not_valid_before(no_ext_now)
        builder = builder.not_valid_after(no_ext_now + data[name]["expires"])
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca.pub.loaded.subject)
        builder = builder.public_key(csr.public_key())

        key = ca.key_backend.get_key(ca, UsePrivateKeyOptions(password=pwd))  # type: ignore[attr-defined]
        x509_cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
        cert = Certificate(ca=ca)
        cert.update_certificate(x509_cert)
        _copy_cert(dest, cert, data[name], key_path, csr_path)

    # create a cert with all extensions that we know
    # NOTE: This certificate is not really a meaningful certificate:
    #   * NameConstraints is only valid for CAs
    #   * KeyUsage and ExtendedKeyUsage are not meaningful
    # TODO: missing: unsupported extensions
    #   * Certificate Policies
    #   * Policy Constraints
    #   * Inhibit anyPolicy
    #   * Freshest CRL
    #   * PrecertificateSignedCertificateTimestamps (cannot be generated by cryptography 2.6:
    #       https://github.com/pyca/cryptography/issues/4531)
    #   * Policy Mappings (not supported by cryptography 2.6:
    #       https://github.com/pyca/cryptography/issues/1947)
    name = "all-extensions"
    ca = CertificateAuthority.objects.get(name=data[name]["ca"])
    key_path = Path(os.path.join(settings.CA_DIR, f"{name}.key"))
    csr_path = Path(os.path.join(settings.CA_DIR, f"{name}.csr"))
    csr_subject = x509.Name(parse_serialized_name_attributes(data[name]["csr_subject"]))
    csr = _create_csr(key_path, csr_path, subject=csr_subject)

    with freeze_time(now + data[name]["delta"]):
        cert = Certificate.objects.create_cert(
            ca=ca,
            key_backend_options=UsePrivateKeyOptions(password=data[ca.name].get("password")),
            csr=csr,
            profile=profiles["webserver"],
            algorithm=data[name].get("algorithm"),
            subject=x509.Name(parse_serialized_name_attributes(data[name]["subject"])),
            expires=data[name]["expires"],
            extensions=data[name]["extensions"].values(),
        )
    _copy_cert(dest, cert, data[name], key_path, csr_path)

    # Create a certificate with some alternative form of extension that might otherwise be untested:
    # * CRL with relative_name (full_name and relative_name are mutually exclusive!)
    name = "alt-extensions"
    ca = CertificateAuthority.objects.get(name=data[name]["ca"])
    key_path = Path(os.path.join(settings.CA_DIR, f"{name}.key"))
    csr_path = Path(os.path.join(settings.CA_DIR, f"{name}.csr"))
    csr_subject = x509.Name(parse_serialized_name_attributes(data[name]["csr_subject"]))
    csr = _create_csr(key_path, csr_path, subject=csr_subject)

    with freeze_time(now + data[name]["delta"]):
        cert = Certificate.objects.create_cert(
            ca=ca,
            key_backend_options=UsePrivateKeyOptions(password=data[ca.name].get("password")),
            csr=csr,
            profile=profiles["webserver"],
            algorithm=data[name].get("algorithm"),
            subject=x509.Name(parse_serialized_name_attributes(data[name]["subject"])),
            expires=data[name]["expires"],
            extensions=data[name]["extensions"].values(),
        )
    _copy_cert(dest, cert, data[name], key_path, csr_path)

    # Create a certificate with no subjects
    name = "empty-subject"
    ca = CertificateAuthority.objects.get(name=data[name]["ca"])
    key_path = Path(os.path.join(settings.CA_DIR, f"{name}.key"))
    csr_path = Path(os.path.join(settings.CA_DIR, f"{name}.csr"))
    csr_subject = x509.Name(parse_serialized_name_attributes(data[name]["csr_subject"]))
    csr = _create_csr(key_path, csr_path, subject=csr_subject)

    freeze_now = now
    if delay:
        freeze_now += data[name]["delta"]
    with freeze_time(freeze_now):
        no_ext_now = datetime.now(tz=tz.utc).replace(tzinfo=None)
        pwd = data[ca.name].get("password")

        builder = x509.CertificateBuilder()
        builder = builder.not_valid_before(no_ext_now)
        builder = builder.not_valid_after(no_ext_now + data[name]["expires"])
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(x509.Name([]))
        builder = builder.issuer_name(x509.Name([]))
        builder = builder.public_key(csr.public_key())
        for ext in data[name]["extensions"].values():
            builder = builder.add_extension(ext.value, ext.critical)

        key = ca.key_backend.get_key(ca, UsePrivateKeyOptions(password=pwd))  # type: ignore[attr-defined]
        x509_cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
        cert = Certificate(ca=ca)
        cert.update_certificate(x509_cert)

    _copy_cert(dest, cert, data[name], key_path, csr_path)


def regenerate_ocsp_files(dest: Path, data: CertFixtureData) -> dict[str, OcspFixtureData]:
    """Regenerate OCSP example requests."""
    ocsp_data: dict[str, OcspFixtureData] = {
        "nonce": {"name": "nonce", "filename": "nonce.req"},
        "no-nonce": {"name": "no-nonce", "filename": "no-nonce.req"},
    }
    ocsp_base = dest / "ocsp"
    if not os.path.exists(ocsp_base):
        os.makedirs(ocsp_base)
    ocsp_builder = ocsp.OCSPRequestBuilder()
    ocsp_builder = ocsp_builder.add_certificate(
        data["child-cert"]["parsed_cert"].pub.loaded,
        CertificateAuthority.objects.get(name=data["child-cert"]["ca"]).pub.loaded,
        hashes.SHA1(),
    )

    no_nonce_req = ocsp_builder.build().public_bytes(Encoding.DER)
    with open(ocsp_base / ocsp_data["no-nonce"]["filename"], "wb") as stream:
        stream.write(no_nonce_req)

    nonce = os.urandom(16)
    ocsp_data["nonce"]["nonce"] = bytes_to_hex(nonce)
    ocsp_builder = ocsp_builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    nonce_req = ocsp_builder.build().public_bytes(Encoding.DER)
    with open(ocsp_base / ocsp_data["nonce"]["filename"], "wb") as stream:
        stream.write(nonce_req)
    return ocsp_data
