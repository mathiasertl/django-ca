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
import importlib
import typing
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPublicKeyTypes

from django_ca import ca_settings, constants
from django_ca.typehints import AllowedHashTypes, ArgumentGroup, ParsableKeyType

if typing.TYPE_CHECKING:
    from django_ca.models import CertificateAuthority


Self = typing.TypeVar("Self", bound="KeyBackend")  # pragma: only py<3.11  # replace with typing.Self


class KeyBackend(abc.ABC):
    """Base class for all key storage backends.

    All implementations of a key storage backend must implement this abstract base class.
    """

    #: Name (alias) for this backend used for the ``--key-backend`` option.
    name: typing.ClassVar[str]

    #: Title used for the ArgumentGroup in :command:`manage.py init_ca`.
    title: typing.ClassVar[str]

    #: Description used for the ArgumentGroup in :command:`manage.py init_ca`.
    description: typing.ClassVar[str]

    #: The certificate authority handled by this backend.
    ca: Optional["CertificateAuthority"]

    #: The certificate authority handled by this backend.
    ca: Optional["CertificateAuthority"]

    def __init__(self, ca: Optional["CertificateAuthority"] = None, **kwargs: Any) -> None:
        self.ca = ca
        for key, value in kwargs.items():
            setattr(self, key, value)

    @property
    def class_path(self) -> str:
        """Shortcut returning the full Python class path of this instance."""
        return f"{self.__class__.__module__}.{self.__class__.__name__}"

    @classmethod
    def add_private_key_arguments(cls, group: ArgumentGroup) -> None:
        """Add arguments for private key generation with this backend.

        Add arguments that can be used for generating private keys with your backend to `group`. The arguments
        you add here are expected to be loaded (and validated) using
        :py:func:`~django_ca.backends.base.KeyBackend.load_from_options`.
        """
        return None

    @classmethod
    def add_parent_private_key_arguments(cls, group: ArgumentGroup) -> None:
        """Add arguments for loading the private key of any signing certificate authority.

        Only add arguments here if you do not want to store options in the database. For example, the
        Storages backend adds the password to load the parents private key here (which is **not** stored in
        the database).
        """
        return None

    @classmethod
    @abc.abstractmethod
    def load_from_options(cls: Type[Self], key_type: ParsableKeyType, options: Dict[str, Any]) -> Self:
        """Create a backend instance from command line options.

        After calling this function, the instance is expected to be able to create and store the private key
        for this certificate authority and subsequently use it for signing new certificates (such as the
        certificate authority itself).

        The `options` dict represents the options added via the ``init_ca`` argument parser, minus values
        that are explicitly named in its ``handle()`` function. It will thus contain all options you added in
        :py:func:`~django_ca.backends.base.KeyBackend.add_private_key_arguments`.

        This method should raise ValueError if any of the arguments are not valid.

        Example::

            class CustomKeyBackend(KeyBackend):
                @classmethod
                def add_private_key_arguments(cls, group: ArgumentGroup) -> None:
                    group.add_argument("--example")

                @classmethod
                def load_from_options(
                    cls, key_type: ParsableKeyType, options: Dict[str, Any]
                ) -> CustomKeyBackend:
                    if options["example"] == "wrong value":  # a contrived example
                        raise ValueError("example must not be 'wrong value'")

                    # the returned instance is ready to call initialize()
                    return cls(example=example)
        """

    @classmethod
    def get_parent_backend_options(cls, options: Dict[str, Any]) -> Dict[str, Any]:
        return {}

    @property
    @abc.abstractmethod
    def usable(self) -> bool:
        """Boolean whether the current process can use this backend to sign a certificate."""

    @abc.abstractmethod
    def initialize(self, key_type: Optional[ParsableKeyType]) -> CertificateIssuerPublicKeyTypes:
        """Initialize the CA."""

    @abc.abstractmethod
    def sign_certificate(
        self,
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
        self, builder: x509.CertificateRevocationListBuilder, algorithm: Optional[AllowedHashTypes]
    ) -> x509.CertificateRevocationList:
        """Sign a certificate revocation list request."""

    def get_ocsp_key_size(self) -> int:
        """Get the default key size for OCSP keys. This is only called for RSA or DSA keys."""
        return ca_settings.CA_DEFAULT_KEY_SIZE

    def get_ocsp_key_elliptic_curve(self) -> ec.EllipticCurve:
        """Get the default elliptic curve for OCSP keys. This is only called for elliptic curve keys."""
        return ca_settings.CA_DEFAULT_ELLIPTIC_CURVE()


def get_key_backend_class(path: str) -> Type["KeyBackend"]:
    """Get a backend class by the given class path.

    Raises ValueError if the class cannot be imported or is not a subclass of KeyBackend.
    """
    try:
        module_path, class_name = path.rsplit(".", 1)
    except ValueError as ex:
        raise ValueError(
            f'{path}: Must be a full class path (e.g. "{constants.DEFAULT_STORAGE_BACKEND}".'
        ) from ex

    # Import the module
    try:
        module = importlib.import_module(module_path)
    except ModuleNotFoundError as ex:
        raise ValueError(f"{module_path}: Module not found.") from ex

    # Get the class
    try:
        cls = getattr(module, class_name)
    except AttributeError as ex:
        raise ValueError(f"{class_name}: Not found in {module_path}.") from ex

    # Make sure it's a subclass of KeyBackend.
    if not issubclass(cls, KeyBackend):
        raise ValueError(f"{path}: Not a subclass of {KeyBackend.__module__}.{KeyBackend.__name__}.")
    return typing.cast(Type[KeyBackend], cls)  # validated in check just above


def get_key_backend_classes() -> Dict[str, Type["KeyBackend"]]:
    """Get all key backend classes defined by the ``CA_KEY_BACKENDS`` setting."""
    return {path: get_key_backend_class(path) for path in ca_settings.CA_KEY_BACKENDS}
