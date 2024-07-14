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

"""Base classes for CA backends."""

import abc
import typing
from collections.abc import Iterator, Sequence
from datetime import datetime
from threading import local
from typing import Annotated, Any, Optional

from pydantic import BaseModel, Field, model_validator

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificateIssuerPublicKeyTypes,
)

from django.core.exceptions import ImproperlyConfigured
from django.core.management import CommandParser
from django.utils.module_loading import import_string

from django_ca import constants
from django_ca.conf import KeyBackendConfigurationModel, model_settings
from django_ca.pydantic.type_aliases import PowerOfTwoInt
from django_ca.typehints import (
    AllowedHashTypes,
    ArgumentGroup,
    CertificateExtension,
    HashAlgorithms,
    ParsableKeyType,
)

if typing.TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


# NOTE: Self only needed before Python3.11, replace with typing.Self then
Self = typing.TypeVar("Self", bound="KeyBackend[BaseModel,BaseModel,BaseModel]")  # pragma: only py<3.11
CreatePrivateKeyOptionsTypeVar = typing.TypeVar("CreatePrivateKeyOptionsTypeVar", bound=BaseModel)
UsePrivateKeyOptionsTypeVar = typing.TypeVar("UsePrivateKeyOptionsTypeVar", bound=BaseModel)
StorePrivateKeyOptionsTypeVar = typing.TypeVar("StorePrivateKeyOptionsTypeVar", bound=BaseModel)


class CreatePrivateKeyOptionsBaseModel(BaseModel):
    """Base model for creating private keys that shares common fields and validators."""

    key_type: ParsableKeyType
    key_size: Optional[Annotated[PowerOfTwoInt, Field(ge=model_settings.CA_MIN_KEY_SIZE)]] = None

    @model_validator(mode="after")
    def validate_key_size(self) -> "typing.Self":
        """Validate that the key size is not set for invalid key types."""
        if self.key_type in ("RSA", "DSA") and self.key_size is None:
            self.key_size = model_settings.CA_DEFAULT_KEY_SIZE
        elif self.key_type not in ("RSA", "DSA") and self.key_size is not None:
            raise ValueError(f"Key size is not supported for {self.key_type} keys.")
        return self


class KeyBackend(
    typing.Generic[
        CreatePrivateKeyOptionsTypeVar, StorePrivateKeyOptionsTypeVar, UsePrivateKeyOptionsTypeVar
    ],
    metaclass=abc.ABCMeta,
):
    """Base class for all key storage backends.

    All implementations of a key storage backend must implement this abstract base class.
    """

    #: Alias under which this backend is configured under settings.KEY_BACKENDS.
    alias: str

    #: Private key types supported by the key backend. This defines the choices for the ``--key-type``
    #: argument and the `key_type` parameter in
    #: :py:func:`~django_ca.key_backends.base.KeyBackend.get_create_private_key_options` is guaranteed to be
    #: one of the named values.
    supported_key_types: tuple[str, ...]

    #: Hash algorithms supported by the key backend. This defines the choices for the ``--algorithm`` argument
    #: and the `algorithm` argument in :py:func:`~django_ca.key_backends.base.KeyBackend.sign_certificate` is
    #: guaranteed to be one of the named values.
    supported_hash_algorithms: tuple[HashAlgorithms, ...] = tuple(constants.HASH_ALGORITHM_TYPES)

    #: Elliptic curves supported by this backend for elliptic curve keys. This defines the choices for the
    #: ``--elliptic-curve`` parameter and the `elliptic_curve` parameter in
    #: :py:func:`~django_ca.key_backends.base.KeyBackend.get_create_private_key_options` is guaranteed to be
    #: one of the named values if ``--key-type=EC`` is passed.
    supported_elliptic_curves: tuple[str, ...]

    #: Title used for the ArgumentGroup in :command:`manage.py init_ca`.
    title: typing.ClassVar[str]

    #: Description used for the ArgumentGroup in :command:`manage.py init_ca`.
    description: typing.ClassVar[str]

    #: The Pydantic model representing the options used for loading a private key.
    use_model: type[UsePrivateKeyOptionsTypeVar]

    #: Prefix for argparse to use for arguments. Empty for the default alias, and `{alias}-` otherwise.
    argparse_prefix: str = ""

    #: Prefix to use for loading options. Empty for the default alias, and `{alias}_` otherwise.
    options_prefix: str = ""

    def __init__(self, alias: str, **kwargs: Any) -> None:
        self.alias = alias

        if self.alias != model_settings.CA_DEFAULT_KEY_BACKEND:
            self.argparse_prefix = f"{alias.lower().replace('_', '-')}-"
            self.options_prefix = f"{alias.lower().replace('-', '_')}_"

        for key, value in kwargs.items():
            setattr(self, key, value)

    def add_create_private_key_group(self, parser: CommandParser) -> Optional[ArgumentGroup]:
        """Add an argument group for arguments for private key generation with this backend.

        By default, the title and description of the argument group is based on
        :py:attr:`~django_ca.key_backends.base.KeyBackend.alias`,
        :py:attr:`~django_ca.key_backends.base.KeyBackend.title` and
        :py:attr:`~django_ca.key_backends.base.KeyBackend.description`.

        Return ``None`` if you don't need to create such a group.
        """
        return parser.add_argument_group(
            f"{self.alias}: {self.title}",
            f"The backend used with --key-backend={self.alias}. {self.description}",
        )

    def add_store_private_key_group(self, parser: CommandParser) -> Optional[ArgumentGroup]:
        """Add an argument group for storing private keys (when importing an existing CA).

        By default, this method adds the same group as
        :py:func:`~django_ca.key_backends.base.KeyBackend.add_create_private_key_group`
        """
        return self.add_create_private_key_group(parser)

    def add_use_private_key_group(self, parser: CommandParser) -> Optional[ArgumentGroup]:
        """Add an argument group for arguments required for using a private key stored with this backend.

        By default, the title and description of the argument group is based on
        :py:attr:`~django_ca.key_backends.base.KeyBackend.alias` and
        :py:attr:`~django_ca.key_backends.base.KeyBackend.title`.

        Return ``None`` if you don't need to create such a group.
        """
        return parser.add_argument_group(
            f"{self.alias} key storage",
            f"Arguments for using private keys stored with the {self.alias} backend.",
        )

    @abc.abstractmethod
    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        """Add arguments for private key generation with this backend.

        Add arguments that can be used for generating private keys with your backend to `group`. The arguments
        you add here are expected to be loaded (and validated) using
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_create_private_key_options`.
        """

    @abc.abstractmethod
    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        """Add arguments for loading the private key of a parent certificate authority.

        The arguments you add here are expected to be loaded (and validated) using
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_use_parent_private_key_options`.
        """

    @abc.abstractmethod
    def add_store_private_key_arguments(self, group: ArgumentGroup) -> None:
        """Add arguments for storing private keys (when importing an existing CA)."""

    # pylint: disable=unused-argument  # Method may not be overwritten, just providing default here
    def add_use_private_key_arguments(self, group: ArgumentGroup) -> None:
        """Add arguments required for using private key stored with this backend.

        The arguments you add here are expected to be loaded (and validated) using
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_use_parent_private_key_options`.
        """
        return None

    @abc.abstractmethod
    def get_create_private_key_options(
        self,
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[str],
        options: dict[str, Any],
    ) -> CreatePrivateKeyOptionsTypeVar:
        """Get options to create private keys into a Pydantic model.

        `options` is the dictionary of arguments from :command:`manage.py init_ca` (including default values).
        The returned model will be passed to
        :py:func:`~django_ca.key_backends.base.KeyBackend.create_private_key`.
        """

    @abc.abstractmethod
    def get_use_parent_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> UsePrivateKeyOptionsTypeVar:
        """Get options to use the private key of a parent certificate authority.

        The returned model will be used for the certificate authority `ca`. You can pass it as extra context
        to influence model validation.

        `options` is the dictionary of arguments to :command:`manage.py init_ca` (including default values).
        The key backend is expected to be able to sign certificate authorities using the options provided
        here.
        """

    @abc.abstractmethod
    def get_use_private_key_options(
        self, ca: "CertificateAuthority", options: dict[str, Any]
    ) -> UsePrivateKeyOptionsTypeVar:
        """Get options to use the private key of a certificate authority.

        The returned model will be used for the certificate authority `ca`. You can pass it as extra context
        to influence model validation.

        `options` is the dictionary of arguments to :command:`manage.py init_ca` (including default values).
        The key backend is expected to be able to sign certificates and CRLs using the options provided here.
        """

    @abc.abstractmethod
    def get_store_private_key_options(self, options: dict[str, Any]) -> StorePrivateKeyOptionsTypeVar:
        """Get options used when storing private keys."""

    @abc.abstractmethod
    def is_usable(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: Optional[UsePrivateKeyOptionsTypeVar] = None,
    ) -> bool:
        """Boolean returning if the given `ca` can be used to sign new certificates (or CRLs).

        The `options` are the options returned by
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_use_private_key_options`. It may be ``None`` in
        cases where key options cannot (yet) be loaded. If ``None``, the backend should return ``False`` if it
        knows for sure that it will not be usable, and ``True`` if usability cannot be determined.
        """

    @abc.abstractmethod
    def check_usable(
        self, ca: "CertificateAuthority", use_private_key_options: UsePrivateKeyOptionsTypeVar
    ) -> None:
        """Check if the given CA is usable, raise ValueError if not.

        The `options` are the options returned by
        :py:func:`~django_ca.key_backends.base.KeyBackend.get_use_private_key_options`. It may be ``None`` in
        cases where key options cannot (yet) be loaded. If ``None``, the backend should return ``False`` if it
        knows for sure that it will not be usable, and ``True`` if usability cannot be determined.
        """

    @abc.abstractmethod
    def create_private_key(
        self, ca: "CertificateAuthority", key_type: ParsableKeyType, options: CreatePrivateKeyOptionsTypeVar
    ) -> tuple[CertificateIssuerPublicKeyTypes, UsePrivateKeyOptionsTypeVar]:
        """Create a private key for the certificate authority.

        The method is expected to set `key_backend_options` on `ca` with a set of options that can later be
        used to load the private key. Since this value will be stored in the database, you should not add
        secrets to `key_backend_options`.

        Note that `ca` is not yet a *saved* database entity, so fields are only partially populated.
        """

    @abc.abstractmethod
    def store_private_key(
        self,
        ca: "CertificateAuthority",
        key: CertificateIssuerPrivateKeyTypes,
        certificate: x509.Certificate,
        options: StorePrivateKeyOptionsTypeVar,
    ) -> None:
        """Store a private key for the certificate authority.

        The method is expected to set `key_backend_options` on `ca` with a set of options that can later be
        used to load the private key. Since this value will be stored in the database, you should not add
        secrets to `key_backend_options`.

        Note that `ca` is not yet a *saved* database entity, so fields are only partially populated.
        """

    @abc.abstractmethod
    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: UsePrivateKeyOptionsTypeVar,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: Optional[AllowedHashTypes],
        issuer: x509.Name,
        subject: x509.Name,
        expires: datetime,
        # NOTE: Allows any extension, as the function is also used for creating certificate authorities.
        extensions: Sequence[CertificateExtension],
    ) -> x509.Certificate:
        """Sign a certificate."""

    @abc.abstractmethod
    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        use_private_key_options: UsePrivateKeyOptionsTypeVar,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        """Sign a certificate revocation list request."""

    def get_ocsp_key_size(
        self,
        ca: "CertificateAuthority",  # pylint: disable=unused-argument
        use_private_key_options: UsePrivateKeyOptionsTypeVar,  # pylint: disable=unused-argument
    ) -> int:
        """Get the default key size for OCSP keys. This is only called for RSA or DSA keys."""
        return model_settings.CA_DEFAULT_KEY_SIZE

    def get_ocsp_key_elliptic_curve(
        self,
        ca: "CertificateAuthority",  # pylint: disable=unused-argument
        use_private_key_options: UsePrivateKeyOptionsTypeVar,  # pylint: disable=unused-argument
    ) -> ec.EllipticCurve:
        """Get the default elliptic curve for OCSP keys. This is only called for elliptic curve keys."""
        return model_settings.CA_DEFAULT_ELLIPTIC_CURVE

    def validate_signature_hash_algorithm(
        self,
        key_type: ParsableKeyType,
        algorithm: Optional[AllowedHashTypes],
        default: Optional[AllowedHashTypes] = None,
    ) -> Optional[AllowedHashTypes]:
        """Give a backend the opportunity to check the signature hash algorithm or return the default value.

        The `algorithm` is the one selected by the user, or ``None`` if no algorithm was selected. The
        `default` reflects the signature algorithm of a signing certificate authority and is ``None`` only
        when creating a root certificate authority.

        Any backend implementation should raise ``ValueError`` if it wants to veto a particular combination of
        key type and algorithm.
        """
        if key_type not in ("DSA", "RSA", "EC"):
            if algorithm is not None:
                raise ValueError(f"{key_type} keys do not allow an algorithm for signing.")

            return None

        # Compute the default hash algorithm
        if algorithm is None:
            if default is not None:
                algorithm = default
            elif key_type == "DSA":
                algorithm = model_settings.CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM
            else:
                algorithm = model_settings.CA_DEFAULT_SIGNATURE_HASH_ALGORITHM

        name = constants.HASH_ALGORITHM_NAMES[type(algorithm)]

        # Make sure that the selected signature hash algorithm works for this backend.
        if name not in self.supported_hash_algorithms:
            raise ValueError(f"{name}: Algorithm not supported by {self.alias} key backend.")
        return algorithm


class KeyBackends:
    """A key backend handler similar to Django's storages or caches handler."""

    def __init__(self) -> None:
        self._backends = local()

    def __getitem__(self, name: str) -> KeyBackend[BaseModel, BaseModel, BaseModel]:
        try:
            return typing.cast(KeyBackend[BaseModel, BaseModel, BaseModel], self._backends.backends[name])
        except AttributeError:
            self._backends.backends = {}  # first backend is loaded
        except KeyError:
            pass  # this backend not yet loaded

        self._backends.backends[name] = self._get_key_backend(name)
        # TYPEHINT NOTE: _get_key_backend should not write anything into this variable
        return self._backends.backends[name]  # type: ignore[no-any-return]

    def __iter__(self) -> Iterator[KeyBackend[BaseModel, BaseModel, BaseModel]]:
        for name in model_settings.CA_KEY_BACKENDS:
            yield self[name]

    def _reset(self) -> None:
        self._backends = local()

    def _get_key_backend(self, alias: str) -> KeyBackend[BaseModel, BaseModel, BaseModel]:
        """Get the key backend with the given alias."""
        try:
            configuration: KeyBackendConfigurationModel = model_settings.CA_KEY_BACKENDS[alias]
        except KeyError as ex:
            raise ValueError(f"{alias}: key backend is not configured.") from ex

        backend = configuration.BACKEND
        options = configuration.OPTIONS.copy()
        try:
            backend_cls = import_string(backend)
        except ImportError as ex:
            raise ImproperlyConfigured(f"Could not find backend {backend!r}: {ex}") from ex

        if not issubclass(backend_cls, KeyBackend):
            raise ImproperlyConfigured(f"{backend}: Class does not refer to a key backend.")

        # TYPEHINT NOTE: we check for the correct subclass above.
        return backend_cls(alias, **options)  # type: ignore[no-any-return]


key_backends = KeyBackends()
