from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPublicKeyTypes,
)

from django_ca.key_backends import KeyBackend
from django_ca.management.actions import PasswordAction
from django_ca.typehints import ArgumentGroup, ParsableKeyType
from pydantic import BaseModel

if TYPE_CHECKING:  # protected by TYPE_CHECKING to avoid circular imports
    from django_ca.models import CertificateAuthority

# {Create,Store,Use}PrivatekeyOptions actually defined above,
# using only shortcuts here:
CreatePrivateKeyOptions = BaseModel
StorePrivateKeyOptions = BaseModel
UsePrivateKeyOptions = BaseModel


class MyStoragesBackend(
    KeyBackend[CreatePrivateKeyOptions, StorePrivateKeyOptions, UsePrivateKeyOptions]
):
    """Custom key backend."""

    # constructor/attributes defined above already
    # def __init__(...): ...

    # Password is needed in multiple places, so create a re-usable function
    def _add_password_argument(
        self,
        group: ArgumentGroup,
        opt: str = "--password",
        prompt: str = "Password for CA: ",
    ) -> None:
        group.add_argument(
            opt,
            nargs="?",
            action=PasswordAction,
            prompt=prompt,
        )

    # Add the arguments for your backend to "manage.py init_ca":
    def add_create_private_key_arguments(self, group: ArgumentGroup) -> None:
        group.add_argument("--key-size", type=int)
        group.add_argument("--path", type=Path, default=Path("ca"))
        self._add_password_argument(group)
        ...

    # If init_ca creates an intermediate CA, it might need a password to load
    # its private key
    def add_use_parent_private_key_arguments(self, group: ArgumentGroup) -> None:
        self._add_password_argument(
            group, opt="--parent-password", prompt="Password for parent CA: "
        )

    # Transform arguments added above into a Pydantic model that contains all
    # information to create a private key. The keys for ``options``
    # correspond to the "destination" of the argparse arguments.
    #
    # Since `supported_key_types` defines  that this backend only supports RSA keys, we
    # know that `key_type` will be "RSA" here.
    def get_create_private_key_options(
        self, key_type: Literal["RSA"], options: dict[str, Any]
    ) -> CreatePrivateKeyOptions:
        return CreatePrivateKeyOptions(
            password=options["password"],
            path=options["path"],
            key_size=options["key_size"],
        )

    # Get the model to use the parents private key, if any.
    def get_use_parent_private_key_options(
        self, options: dict[str, Any]
    ) -> UsePrivateKeyOptions:
        return UsePrivateKeyOptions(password=options["parent_password"])

    # Create and store the private key, store database options and return
    # public key and use-model:
    # NOTE: when using the private key, the ``ca.key_backend_options`` and
    # the returned model will be all the information you have to use it.
    def create_private_key(
        self,
        ca: "CertificateAuthority",
        key_type: ParsableKeyType,
        # from get_create_private_key_options():
        options: CreatePrivateKeyOptions,
    ) -> tuple[CertificateIssuerPublicKeyTypes, UsePrivateKeyOptions]:
        # Create the private key and store on filesystem:
        key = ...
        path = ...

        # Store absolute path to private key in database (can contain any
        # JSON-serializable dict):
        ca.key_backend_options = {"path": path}

        # Get model to use the private key later
        use_private_key_options = UsePrivateKeyOptions.model_validate(
            {"password": options.password}, context={"ca": ca}
        )

        return key.public_key(), use_private_key_options

    def sign_certificate(
        self,
        ca: "CertificateAuthority",
        # from create_private_key():
        use_private_key_options: UsePrivateKeyOptions,
        public_key: CertificateIssuerPublicKeyTypes,
        # ...
    ) -> x509.Certificate:
        # load stored private key from ``ca.key_backend_options["path"]``
        # decrypt with ``use_private_key_options.password``
        ...
