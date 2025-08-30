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

"""Key backend using the Django Storages system."""

import typing
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, load_pem_private_key

from django.core.management import CommandParser

from django_ca import constants
from django_ca.key_backends import KeyBackend
from django_ca.key_backends.db.models import (
    DBCreatePrivateKeyOptions,
    DBStorePrivateKeyOptions,
    DBUsePrivateKeyOptions,
)
from django_ca.models import CertificateAuthority
from django_ca.typehints import (
    ArgumentGroup,
    CertificateExtension,
    EllipticCurveName,
    ParsableKeyType,
    SignatureHashAlgorithm,
)
from django_ca.utils import generate_private_key, get_cert_builder


class DBBackend(KeyBackend[DBCreatePrivateKeyOptions, DBStorePrivateKeyOptions, DBUsePrivateKeyOptions]):
    """The default storage backend that uses Django's file storage API."""

    name = "storages"
    title = "Store private keys using the Django file storage API"
    description = (
        "It is most commonly used to store private keys on the file system. Custom file storage backends can "
        "be used to store keys on other systems (e.g. a cloud storage system)."
    )
    use_model = DBUsePrivateKeyOptions

    supported_key_types: tuple[ParsableKeyType, ...] = constants.PARSABLE_KEY_TYPES
    supported_elliptic_curves: tuple[EllipticCurveName, ...] = tuple(constants.ELLIPTIC_CURVE_TYPES)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DBBackend)

    def __hash__(self) -> int:  # pragma: no cover
        return hash(id(self))

    def add_create_private_key_group(self, parser: CommandParser) -> ArgumentGroup | None:
        return None

    def add_store_private_key_group(self, parser: CommandParser) -> ArgumentGroup | None:
        return None

    def add_use_private_key_group(self, parser: CommandParser) -> ArgumentGroup | None:
        return None

    def get_create_private_key_options(
        self,
        key_type: ParsableKeyType,
        key_size: int | None,
        elliptic_curve: EllipticCurveName | None,  # type: ignore[override]
        options: dict[str, Any],
    ) -> DBCreatePrivateKeyOptions:
        return DBCreatePrivateKeyOptions(key_type=key_type, key_size=key_size, elliptic_curve=elliptic_curve)

    def get_store_private_key_options(self, options: dict[str, Any]) -> DBStorePrivateKeyOptions:
        return DBStorePrivateKeyOptions()

    def get_use_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> DBUsePrivateKeyOptions:
        return DBUsePrivateKeyOptions.model_validate({}, context={"ca": ca, "backend": self}, strict=True)

    def get_use_parent_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> DBUsePrivateKeyOptions:
        return DBUsePrivateKeyOptions.model_validate({}, context={"ca": ca, "backend": self}, strict=True)

    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: ParsableKeyType,
        options: DBCreatePrivateKeyOptions,
    ) -> tuple[CertificateIssuerPublicKeyTypes, DBUsePrivateKeyOptions]:
        encryption = serialization.NoEncryption()
        key = generate_private_key(options.key_size, key_type, options.get_elliptic_curve())
        pem = key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )
        ca.key_backend_options = {"private_key": {"pem": pem.decode()}}
        use_private_key_options = DBUsePrivateKeyOptions.model_validate(
            {}, context={"ca": ca, "backend": self}
        )
        return key.public_key(), use_private_key_options

    def store_private_key(
        self,
        ca: "CertificateAuthority",
        key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate,
        options: DBStorePrivateKeyOptions,
    ) -> None:
        encryption = serialization.NoEncryption()
        pem = key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
        )
        ca.key_backend_options = {"private_key": {"pem": pem.decode()}}

    def get_key(
        self,
        ca: "CertificateAuthority",
        # pylint: disable-next=unused-argument  # interface requires option
        use_private_key_options: DBUsePrivateKeyOptions,
    ) -> CertificateIssuerPrivateKeyTypes:
        """The CAs private key as private key."""
        pem = ca.key_backend_options["private_key"]["pem"].encode()
        return typing.cast(  # type validated below
            CertificateIssuerPrivateKeyTypes, load_pem_private_key(pem, None)
        )

    def is_usable(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DBUsePrivateKeyOptions | None = None,
    ) -> bool:
        # If key_backend_options is not set or path is not set, it is certainly unusable.
        if not ca.key_backend_options or not ca.key_backend_options.get("private_key"):
            return False
        return True

    def check_usable(
        self, ca: "CertificateAuthority", use_private_key_options: DBUsePrivateKeyOptions
    ) -> None:
        """Check if the given CA is usable, raise ValueError if not.

        The `options` are the options returned by
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_use_private_key_options`. It may be ``None`` in
        cases where key options cannot (yet) be loaded. If ``None``, the backend should return ``False`` if it
        knows for sure that it will not be usable, and ``True`` if usability cannot be determined.
        """
        if not ca.key_backend_options or not ca.key_backend_options.get("private_key"):
            raise ValueError(f"{ca.key_backend_options}: Private key not stored in database.")

    def sign_data(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DBUsePrivateKeyOptions,
        data: bytes,
        algorithm: hashes.HashAlgorithm | Prehashed | None = None,
        padding: AsymmetricPadding | None = None,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm | None = None,
    ) -> bytes:
        private_key = self.get_key(ca, use_private_key_options)

        kwargs: dict[str, Any] = {}
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            if signature_algorithm is None:
                raise ValueError("signature_algorithm is required for elliptic curve keys.")
            kwargs["signature_algorithm"] = signature_algorithm
        elif isinstance(private_key, rsa.RSAPrivateKey):
            if algorithm is None:
                raise ValueError("algorithm is required for RSA keys.")
            if padding is None:
                raise ValueError("padding is required for RSA keys.")
            kwargs["padding"] = padding
            kwargs["algorithm"] = algorithm
        elif isinstance(private_key, dsa.DSAPrivateKey):
            kwargs["algorithm"] = algorithm
            if algorithm is None:
                raise ValueError("algorithm is required for DSA keys.")
        elif algorithm is not None or padding is not None or signature_algorithm is not None:
            raise ValueError("algorithm, padding and signature_algorithm are not allowed for this key type.")

        return private_key.sign(data, **kwargs)

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DBUsePrivateKeyOptions,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: SignatureHashAlgorithm | None,
        issuer: x509.Name,
        subject: x509.Name,
        not_after: datetime,
        extensions: Sequence[CertificateExtension],
    ) -> x509.Certificate:
        builder = get_cert_builder(not_after, serial=serial)
        builder = builder.public_key(public_key)
        builder = builder.issuer_name(issuer)
        builder = builder.subject_name(subject)
        for extension in extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)
        return builder.sign(private_key=self.get_key(ca, use_private_key_options), algorithm=algorithm)

    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: DBUsePrivateKeyOptions,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: SignatureHashAlgorithm | None,
    ) -> x509.CertificateRevocationList:
        return builder.sign(private_key=self.get_key(ca, use_private_key_options), algorithm=algorithm)
