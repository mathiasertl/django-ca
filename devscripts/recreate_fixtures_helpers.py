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

The test suite should be sufficiently modular to still run without errors after running this command."""

import importlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID, NameOID

from django.test.utils import override_settings
from django.urls import reverse

from freezegun import freeze_time

from devscripts import config, utils

from django_ca import ca_settings, constants
from django_ca.extensions import serialize_extension
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import profiles
from django_ca.subject import Subject
from django_ca.utils import bytes_to_hex, ca_storage

DEFAULT_KEY_SIZE = 2048  # Size for private keys
TIMEFORMAT = "%Y-%m-%d %H:%M:%S"


def genpkey(*args: str):
    """Convenience wrapper for the openssl genpkey program."""
    return utils.run(["openssl", "genpkey"] + list(args), stderr=subprocess.DEVNULL)


class CertificateEncoder(json.JSONEncoder):
    """Minor class to encode certificate data into json."""

    def default(self, o):
        if isinstance(o, hashes.HashAlgorithm):
            return o.name
        if isinstance(o, Path):
            return str(o)
        if isinstance(o, x509.Extension):
            return serialize_extension(o)
        return json.JSONEncoder.default(self, o)


def _create_key(path, key_type):
    if key_type == "RSA":
        utils.run(["openssl", "genrsa", "-out", path, str(DEFAULT_KEY_SIZE)], stderr=subprocess.DEVNULL)
    elif key_type == "DSA":
        genpkey(
            "-genparam",
            "-algorithm",
            "DSA",
            "-out",
            path + ".param",
            "-pkeyopt",
            "dsa_paramgen_bits:2048",
            "-pkeyopt",
            "dsa_paramgen_md:sha256",
        )
        genpkey("-paramfile", path + ".param", "-out", path)
    elif key_type == "EC":
        utils.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-out", path],
            stderr=subprocess.DEVNULL,
        )
    elif key_type == "Ed25519":
        genpkey("-algorithm", "ED25519", "-out", path)
    elif key_type == "Ed448":
        genpkey("-algorithm", "ED448", "-out", path)
    else:
        raise ValueError(f"Unknown key type: {key_type}")


def _create_csr(key_path, path, subject="/CN=ignored.example.com", key_type="RSA"):
    _create_key(key_path, key_type)
    utils.run(["openssl", "req", "-new", "-key", key_path, "-out", path, "-utf8", "-batch", "-subj", subject])

    with open(path, encoding="utf-8") as stream:
        csr = stream.read()
    return x509.load_pem_x509_csr(csr.encode("utf-8"))


def _update_cert_data(cert, data):
    data["serial"] = cert.serial
    data["hpkp"] = cert.hpkp_pin
    data["valid_from"] = cert.pub.loaded.not_valid_before.strftime(TIMEFORMAT)
    data["valid_until"] = cert.pub.loaded.not_valid_after.strftime(TIMEFORMAT)

    data["md5"] = cert.get_fingerprint(hashes.MD5())
    data["sha1"] = cert.get_fingerprint(hashes.SHA1())
    data["sha256"] = cert.get_fingerprint(hashes.SHA256())
    data["sha512"] = cert.get_fingerprint(hashes.SHA512())

    for oid, ext in cert.x509_extensions.items():
        ext_key = constants.EXTENSION_KEYS[oid]
        data[ext_key] = serialize_extension(ext)


def _write_ca(dest, ca, cert_data, testserver, password=None):
    key_dest = os.path.join(dest, cert_data["key_filename"])
    pub_dest = os.path.join(dest, cert_data["pub_filename"])
    key_der_dest = os.path.join(dest, cert_data["key_der_filename"])
    pub_der_dest = os.path.join(dest, cert_data["pub_der_filename"])

    # write files to dest
    shutil.copy(ca_storage.path(ca.private_key_path), key_dest)
    with open(pub_dest, "w", encoding="utf-8") as stream:
        stream.write(ca.pub.pem)

    if password is None:
        encryption = NoEncryption()
    else:
        encryption = BestAvailableEncryption(password)

    key_der = ca.key(password=password).private_bytes(
        encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
    )
    with open(key_der_dest, "wb") as stream:
        stream.write(key_der)
    with open(pub_der_dest, "wb") as stream:
        stream.write(ca.pub.der)

    # These keys are only present in CAs:
    ca_crl_path = reverse("django_ca:ca-crl", kwargs={"serial": ca.serial})
    ocsp_cert_post_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": ca.serial})
    cert_data["issuer_url"] = ca.issuer_url
    cert_data["crl_url"] = ca.crl_url
    cert_data["ca_crl_url"] = f"{testserver}{ca_crl_path}"
    cert_data["ocsp_url"] = f"{testserver}{ocsp_cert_post_path}"

    # Update common data for CAs and certs
    _update_cert_data(ca, cert_data)


def _copy_cert(dest, cert, data, key_path, csr_path):
    key_dest = os.path.join(dest, data["key_filename"])
    csr_dest = os.path.join(dest, data["csr_filename"])
    pub_dest = os.path.join(dest, data["pub_filename"])
    key_der_dest = os.path.join(dest, data["key_der_filename"])
    pub_der_dest = os.path.join(dest, data["pub_der_filename"])

    shutil.copy(key_path, key_dest)
    shutil.copy(csr_path, csr_dest)
    with open(pub_dest, "w", encoding="utf-8") as stream:
        stream.write(cert.pub.pem)

    with open(key_dest, "rb") as stream:
        priv_key = stream.read()
    priv_key = load_pem_private_key(priv_key, None)
    key_der = priv_key.private_bytes(
        encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )
    with open(key_der_dest, "wb") as stream:
        stream.write(key_der)
    with open(pub_der_dest, "wb") as stream:
        stream.write(cert.pub.der)

    data["crl"] = cert.ca.crl_url
    data["subject"] = cert.distinguished_name
    data["parsed_cert"] = cert

    _update_cert_data(cert, data)


def _update_contrib(parsed, data, cert, name, filename):
    cert_data = {
        "name": name,
        "cn": cert.cn,
        "cat": "sphinx-contrib",
        "pub_filename": filename,
        "key_filename": False,
        "csr_filename": False,
        "valid_from": parsed.not_valid_before.strftime(TIMEFORMAT),
        "valid_until": parsed.not_valid_after.strftime(TIMEFORMAT),
        "serial": cert.serial,
        "subject": cert.distinguished_name,
        "hpkp": cert.hpkp_pin,
        "md5": cert.get_fingerprint(hashes.MD5()),
        "sha1": cert.get_fingerprint(hashes.SHA1()),
        "sha256": cert.get_fingerprint(hashes.SHA256()),
        "sha512": cert.get_fingerprint(hashes.SHA512()),
    }

    for oid, ext in cert.x509_extensions.items():
        if isinstance(ext.value, x509.UnrecognizedExtension):
            # Currently just some old StartSSL extensions for Netscape (!)
            continue

        ext_key = constants.EXTENSION_KEYS[oid]
        cert_data[ext_key] = serialize_extension(ext)

    try:
        ext = cert.pub.loaded.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
    except x509.ExtensionNotFound:
        pass

    data[name] = cert_data


def _generate_contrib_files(data):
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
        data[name]["pathlen"] = ca.pathlen

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


def create_cas(dest, now, delay, data):
    """Create CAs."""
    testserver = f"http://{ca_settings.CA_DEFAULT_HOSTNAME}"
    ca_names = [v["name"] for k, v in data.items() if v.get("type") == "ca"]

    # sort ca_names so that any children are created last
    ca_names = sorted(ca_names, key=lambda n: data[n].get("parent", ""))
    ca_instances = []

    for name in ca_names:
        kwargs = {}

        # Get some data from the parent, if present
        parent = data[name].get("parent")
        if parent:
            kwargs["parent"] = CertificateAuthority.objects.get(name=parent)
            kwargs["ca_crl_url"] = [data[parent]["ca_crl_url"]]

            # also update data
            data[name]["crl"] = data[parent]["ca_crl_url"]

        freeze_now = now
        if delay:
            freeze_now += data[name]["delta"]

        with freeze_time(freeze_now):
            ca = CertificateAuthority.objects.init(
                name=data[name]["name"],
                password=data[name].get("password"),
                subject=Subject(data[name]["subject"]).name,
                expires=datetime.utcnow() + data[name]["expires"],
                key_type=data[name]["key_type"],
                key_size=data[name].get("key_size"),
                algorithm=data[name].get("algorithm"),
                pathlen=data[name]["pathlen"],
                **kwargs,
            )

        # Same values can only be added here because they require data from the already created CA
        crl_path = reverse("django_ca:crl", kwargs={"serial": ca.serial})
        ca.crl_url = f"{testserver}{crl_path}"
        ca.save()

        ca_instances.append(ca)
        _write_ca(dest, ca, data[name], testserver, password=data[name].get("password"))

    # add parent/child relationships
    data["root"]["children"] = [[data["child"]["name"], data["child"]["serial"]]]
    return ca_instances


def create_certs(dest, cas, now, delay, data):
    """Create regular certificates."""
    # let's create a standard certificate for every CA
    for ca in cas:
        name = f"{ca.name}-cert"
        key_path = os.path.join(ca_settings.CA_DIR, f"{name}.key")
        csr_path = os.path.join(ca_settings.CA_DIR, f"{name}.csr")
        csr = _create_csr(
            key_path,
            csr_path,
            subject=data[name]["csr_subject_str"],
            key_type=data[name]["key_type"],
        )

        freeze_now = now
        if delay:
            freeze_now += data[name]["delta"]

        pwd = data[data[name]["ca"]].get("password")
        subject = Subject(f"/CN={data[name]['cn']}")
        with freeze_time(freeze_now):
            cert = Certificate.objects.create_cert(
                ca=ca,
                csr=csr,
                profile=profiles["server"],
                expires=data[name]["expires"],
                algorithm=data[name]["algorithm"],
                password=pwd,
                subject=subject,
            )
        _copy_cert(dest, cert, data[name], key_path, csr_path)

    # create a cert for every profile
    for profile in ca_settings.CA_PROFILES:
        name = f"profile-{profile}"
        ca = CertificateAuthority.objects.get(name=data[name]["ca"])

        key_path = os.path.join(ca_settings.CA_DIR, f"{name}.key")
        csr_path = os.path.join(ca_settings.CA_DIR, f"{name}.csr")
        csr = _create_csr(
            key_path,
            csr_path,
            subject=data[name]["csr_subject_str"],
            key_type=data[name]["key_type"],
        )

        freeze_now = now
        if delay:
            freeze_now += data[name]["delta"]

        pwd = data[ca.name].get("password")
        subject = Subject(f"/CN={data[name]['cn']}")
        with freeze_time(freeze_now):
            cert = Certificate.objects.create_cert(
                ca=ca,
                csr=csr,
                profile=profiles[profile],
                algorithm=data[name]["algorithm"],
                expires=data[name]["expires"],
                password=pwd,
                subject=subject,
            )

        data[name]["profile"] = profile
        _copy_cert(dest, cert, data[name], key_path, csr_path)


def create_special_certs(dest, now, delay, data):
    """Create special-interest certificates (edge cases etc.)."""
    # create a cert with absolutely no extensions
    name = "no-extensions"
    ca = CertificateAuthority.objects.get(name=data[name]["ca"])
    key_path = os.path.join(ca_settings.CA_DIR, f"{name}.key")
    csr_path = os.path.join(ca_settings.CA_DIR, f"{name}.csr")
    csr = _create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

    freeze_now = now
    if delay:
        freeze_now += data[name]["delta"]
    with freeze_time(freeze_now):
        no_ext_now = datetime.utcnow()
        pwd = data[ca.name].get("password")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, data[name]["cn"])])

        builder = x509.CertificateBuilder()
        builder = builder.not_valid_before(no_ext_now)
        builder = builder.not_valid_after(no_ext_now + data[name]["expires"])
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca.pub.loaded.subject)
        builder = builder.public_key(csr.public_key())

        x509_cert = builder.sign(private_key=ca.key(pwd), algorithm=hashes.SHA256())
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
    key_path = os.path.join(ca_settings.CA_DIR, f"{name}.key")
    csr_path = os.path.join(ca_settings.CA_DIR, f"{name}.csr")
    csr = _create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

    with freeze_time(now + data[name]["delta"]):
        cert = Certificate.objects.create_cert(
            ca=ca,
            csr=csr,
            profile=profiles["webserver"],
            algorithm=data[name].get("algorithm"),
            subject=data[name]["subject"],
            expires=data[name]["expires"],
            password=data[ca.name].get("password"),
            extensions=data[name]["extensions"].values(),
        )
    data[name].update(data[name].pop("extensions"))  # cert_data expects this to be flat
    _copy_cert(dest, cert, data[name], key_path, csr_path)

    # Create a certificate with some alternative form of extension that might otherwise be untested:
    # * CRL with relative_name (full_name and relative_name are mutually exclusive!)
    name = "alt-extensions"
    ca = CertificateAuthority.objects.get(name=data[name]["ca"])
    ca.crl_url = ""
    key_path = os.path.join(ca_settings.CA_DIR, f"{name}.key")
    csr_path = os.path.join(ca_settings.CA_DIR, f"{name}.csr")
    csr = _create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

    with freeze_time(now + data[name]["delta"]):
        cert = Certificate.objects.create_cert(
            ca=ca,
            csr=csr,
            profile=profiles["webserver"],
            algorithm=data[name].get("algorithm"),
            subject=data[name]["subject"],
            expires=data[name]["expires"],
            password=data[ca.name].get("password"),
            extensions=data[name]["extensions"].values(),
        )
    data[name].update(data[name].pop("extensions"))  # cert_data expects this to be flat
    _copy_cert(dest, cert, data[name], key_path, csr_path)


def regenerate_ocsp_files(dest, data):
    """Regenerate OCSP example requests."""
    ocsp_data = {
        "nonce": {"name": "nonce", "filename": "nonce.req"},
        "no-nonce": {"name": "no-nonce", "filename": "no-nonce.req"},
    }
    ocsp_base = os.path.join(dest, "ocsp")
    if not os.path.exists(ocsp_base):
        os.makedirs(ocsp_base)
    ocsp_builder = ocsp.OCSPRequestBuilder()
    ocsp_builder = ocsp_builder.add_certificate(
        data["child-cert"]["parsed_cert"].pub.loaded,
        CertificateAuthority.objects.get(name=data["child-cert"]["ca"]).pub.loaded,
        hashes.SHA1(),
    )

    no_nonce_req = ocsp_builder.build().public_bytes(Encoding.DER)
    with open(os.path.join(ocsp_base, ocsp_data["no-nonce"]["filename"]), "wb") as stream:
        stream.write(no_nonce_req)

    nonce = os.urandom(16)
    ocsp_data["nonce"]["nonce"] = bytes_to_hex(nonce)
    ocsp_builder = ocsp_builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    nonce_req = ocsp_builder.build().public_bytes(Encoding.DER)
    with open(os.path.join(ocsp_base, ocsp_data["nonce"]["filename"]), "wb") as stream:
        stream.write(nonce_req)
    return ocsp_data


class override_tmpcadir(override_settings):  # pylint: disable=invalid-name
    """Simplified copy of the same decorator in tests.base."""

    def enable(self):
        # pylint: disable=attribute-defined-outside-init
        self.options["CA_DIR"] = tempfile.mkdtemp()
        self.mock = patch.object(ca_storage, "location", self.options["CA_DIR"])
        self.mock_ = patch.object(ca_storage, "_location", self.options["CA_DIR"])
        self.mock.start()
        self.mock_.start()

        super().enable()

        self.mockc = patch.object(ca_settings, "CA_DIR", self.options["CA_DIR"])
        self.mockc.start()

    def disable(self):
        super().disable()
        self.mock.stop()
        self.mock_.stop()
        self.mockc.stop()
        shutil.rmtree(self.options["CA_DIR"])
        importlib.reload(ca_settings)
