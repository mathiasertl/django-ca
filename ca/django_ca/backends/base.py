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
from datetime import datetime
from threading import local
from typing import Any, Dict, Iterator, List, Optional, Type

from pydantic import BaseModel

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes,
    CertificateIssuerPrivateKeyTypes,
)

from django.core.exceptions import ImproperlyConfigured
from django.core.management import CommandParser
from django.utils.module_loading import import_string

from django_ca import ca_settings
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, ParsableKeyType

if typing.TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


Self = typing.TypeVar("Self", bound="KeyBackend")  # pragma: only py<3.11  # replace with typing.Self
CreatePrivateKeyOptionsTypeVar = typing.TypeVar("CreatePrivateKeyOptionsTypeVar", bound=BaseModel)
UsePrivateKeyOptionsTypeVar = typing.TypeVar("UsePrivateKeyOptionsTypeVar", bound=BaseModel)
StorePrivateKeyOptionsTypeVar = typing.TypeVar("StorePrivateKeyOptionsTypeVar", bound=BaseModel)


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

    #: Title used for the ArgumentGroup in :command:`manage.py init_ca`.
    title: typing.ClassVar[str]

    #: Description used for the ArgumentGroup in :command:`manage.py init_ca`.
    description: typing.ClassVar[str]

    #: The Pydantic model representing the options used for loading a private key.
    load_model: Type[UsePrivateKeyOptionsTypeVar]

    def __init__(self, alias: str, **kwargs: Any) -> None:
        self.alias = alias
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def class_path(self) -> str:
        """Shortcut returning the full Python class path of this instance."""
        return f"{self.__class__.__module__}.{self.__class__.__name__}"

    def add_private_key_group(self, parser: CommandParser) -> Optional[ArgumentGroup]:
        """Add an argument group for arguments for private key generation with this backend.

        By default, the title and description of the argument group is based on
        :py:attr:`~django_ca.backends.base.KeyBackend.alias`,
        :py:attr:`~django_ca.backends.base.KeyBackend.title` and
        :py:attr:`~django_ca.backends.base.KeyBackend.description`.

        Return ``None`` if you don't need to create such a group.
        """
        return parser.add_argument_group(
            f"{self.alias}: {self.title}",
            f"The backend used with --key-backend={self.alias}. {self.description}",
        )

    def add_store_private_key_group(self, parser: CommandParser) -> Optional[ArgumentGroup]:
        """Add an argument group for storing private keys (when importing an existing CA).

        By default, this method adds the same group as
        :py:func:`~django_ca.backends.base.KeyBackend.add_private_key_group`
        """
        return self.add_private_key_group(parser)

    def add_use_private_key_group(self, parser: CommandParser) -> Optional[ArgumentGroup]:
        """Add an argument group for arguments required for using a private key stored with this backend.

        By default, the title and description of the argument group is based on
        :py:attr:`~django_ca.backends.base.KeyBackend.alias` and
        :py:attr:`~django_ca.backends.base.KeyBackend.title`.

        Return ``None`` if you don't need to create such a group.
        """
        return parser.add_argument_group(
            f"{self.alias} key storage",
            f"Arguments for using private keys stored with the {self.alias} backend.",
        )

    def add_private_key_arguments(self, group: ArgumentGroup) -> None:  # pylint: disable=unused-argument
        """Add arguments for private key generation with this backend.

        Add arguments that can be used for generating private keys with your backend to `group`. The arguments
        you add here are expected to be loaded (and validated) using
        :py:func:`~django_ca.backends.base.KeyBackend.get_create_private_key_options`.
        """
        return None

    # pylint: disable-next=unused-argument
    def add_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        """Add arguments for loading the private key of a parent certificate authority.

        The arguments you add here are expected to be loaded (and validated) using
        :py:func:`~django_ca.backends.base.KeyBackend.get_load_parent_private_key_options`.
        """
        return None

    def add_use_private_key_arguments(self, group: ArgumentGroup) -> None:
        """Add arguments required for using private key stored with this backend.

        The arguments you add here are expected to be loaded (and validated) using
        :py:func:`~django_ca.backends.base.KeyBackend.get_load_parent_private_key_options`.
        """
        return None

    @abc.abstractmethod
    def get_create_private_key_options(
        self, key_type: ParsableKeyType, options: Dict[str, Any]
    ) -> CreatePrivateKeyOptionsTypeVar:
        """Load options to create private keys into a Pydantic model.

        `options` is the dictionary of arguments to ``manage.py init_ca`` (including default values). The
        returned model will be passed to :py:func:`~django_ca.backends.base.KeyBackend.create_private_key`.
        """

    @abc.abstractmethod
    def add_store_private_key_options(self, options: Dict[str, Any]) -> StorePrivateKeyOptionsTypeVar:
        """Add arguments for storing private keys (when importing an existing CA)."""

    @abc.abstractmethod
    def get_load_private_key_options(self, options: Dict[str, Any]) -> UsePrivateKeyOptionsTypeVar:
        """Load options to create private keys into a Pydantic model.

        `options` is the dictionary of arguments to ``manage.py init_ca`` (including default values). The key
        backend is expected to be able to sign certificates and CRLs using the options provided here.
        """

    @abc.abstractmethod
    def get_store_private_key_options(self, options: Dict[str, Any]) -> StorePrivateKeyOptionsTypeVar:
        ...

    @abc.abstractmethod
    def get_load_parent_private_key_options(self, options: Dict[str, Any]) -> UsePrivateKeyOptionsTypeVar:
        """Load options to create private keys into a Pydantic model.

        `options` is the dictionary of arguments to ``manage.py init_ca`` (including default values). The key
        backend is expected to be able to sign certificate authorities using the options provided here.
        """

    @abc.abstractmethod
    def is_usable(self, ca: "CertificateAuthority", options: UsePrivateKeyOptionsTypeVar) -> bool:
        ...

    @abc.abstractmethod
    def create_private_key(
        self, ca: "CertificateAuthority", key_type: ParsableKeyType, options: CreatePrivateKeyOptionsTypeVar
    ) -> CertificateIssuerPublicKeyTypes:
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
        load_options: UsePrivateKeyOptionsTypeVar,
        public_key: CertificateIssuerPublicKeyTypes,
        serial: int,
        algorithm: Optional[AllowedHashTypes],
        issuer: x509.Name,
        subject: x509.Name,
        expires: datetime,
        extensions: List[x509.Extension[x509.ExtensionType]],
    ) -> x509.Certificate:
        """Sign a certificate."""

    @abc.abstractmethod
    def sign_certificate_revocation_list(
        self,
        ca: "CertificateAuthority",
        load_options: UsePrivateKeyOptionsTypeVar,
        builder: x509.CertificateRevocationListBuilder,
        algorithm: Optional[AllowedHashTypes],
    ) -> x509.CertificateRevocationList:
        """Sign a certificate revocation list request."""

    def get_ocsp_key_size(self, ca: "CertificateAuthority", load_options: UsePrivateKeyOptionsTypeVar) -> int:
        """Get the default key size for OCSP keys. This is only called for RSA or DSA keys."""
        return ca_settings.CA_DEFAULT_KEY_SIZE

    def get_ocsp_key_elliptic_curve(
        self, ca: "CertificateAuthority", load_options: UsePrivateKeyOptionsTypeVar
    ) -> ec.EllipticCurve:
        """Get the default elliptic curve for OCSP keys. This is only called for elliptic curve keys."""
        return ca_settings.CA_DEFAULT_ELLIPTIC_CURVE()


class KeyBackends:
    """A key backend handler similar to Django's storages or caches handler."""

    def __init__(self) -> None:
        self._backends = local()

    def __getitem__(self, name: Optional[str]) -> KeyBackend:
        if name is None:
            name = ca_settings.CA_DEFAULT_KEY_BACKEND

        try:
            return typing.cast(KeyBackend, self._backends.backends[name])
        except AttributeError:
            self._backends.backends = {}
        except KeyError:
            pass

        self._backends.backends[name] = self.get_key_backend(name)
        return self._backends.backends[name]

    def __iter__(self) -> Iterator[KeyBackend]:
        for name in ca_settings.CA_KEY_BACKENDS:
            yield self[name]

    def _reset(self) -> None:
        self._backends = local()

    def get_key_backend(self, alias: str) -> KeyBackend:
        try:
            params = ca_settings.CA_KEY_BACKENDS[alias].copy()
        except KeyError as ex:
            raise ImproperlyConfigured(
                f"Could not find config for '{alias}' in settings.CA_KEY_BACKENDS"
            ) from ex
        backend = params.pop("BACKEND")
        options = params.pop("OPTIONS", {})
        try:
            backend_cls = import_string(backend)
        except ImportError as ex:
            raise ImproperlyConfigured(f"Could not find backend {backend!r}: {ex}") from ex
        return backend_cls(alias, **options)


key_backends = KeyBackends()
