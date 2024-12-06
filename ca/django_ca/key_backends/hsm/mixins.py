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

"""Miixin classes for HSM key backends."""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Optional

import pkcs11
from pkcs11 import KeyType, ObjectClass, Session
from pkcs11.util.ec import encode_named_curve_parameters

from asn1crypto.algos import SignedDigestAlgorithmId

from django_ca.key_backends.hsm.keys import (
    PKCS11Ed448PrivateKey,
    PKCS11Ed25519PrivateKey,
    PKCS11EllipticCurvePrivateKey,
    PKCS11PrivateKeyTypes,
    PKCS11RSAPrivateKey,
)
from django_ca.key_backends.hsm.session import SessionPool
from django_ca.typehints import EllipticCurves, ParsableKeyType


class HSMKeyBackendMixin:
    """Mixin providing HSM session related functions."""

    library_path: str
    token: str
    so_pin: Optional[str]
    user_pin: Optional[str]

    def __init__(
        self,
        alias: str,
        library_path: str,
        token: str,
        so_pin: Optional[str] = None,
        user_pin: Optional[str] = None,
    ):
        if so_pin is not None and user_pin is not None:
            raise ValueError(f"{alias}: Set either so_pin or user_pin.")

        super().__init__(  # type: ignore[call-arg]  # intended for use in a mixin
            alias, library_path=library_path, token=token, so_pin=so_pin, user_pin=user_pin
        )

    @contextmanager
    def session(self, so_pin: Optional[str], user_pin: Optional[str], rw: bool = False) -> Iterator[Session]:
        """Shortcut to get a session from the pool."""
        try:
            with SessionPool(self.library_path, self.token, so_pin, user_pin, rw=rw) as session:
                yield session
        # python-pkcs11 provides no useful exception strings, so we re-create exceptions with useful ones that
        # can be sent to the user.
        except pkcs11.UserNotLoggedIn as ex:
            # NOTE: We always authenticate, but some operations are known to require a pin and the underlying
            # pkcs11 library does not support it. The known case is creating a key with a SO pin.
            raise pkcs11.UserNotLoggedIn(
                "An operation required a login, but none was provided. This is most likely a bug in the "
                "underlying library, not in django-ca."
            ) from ex
        except pkcs11.PinIncorrect as ex:
            raise pkcs11.PinIncorrect("Pin incorrect.") from ex  # user supplied incorrect pin
        except pkcs11.NoSuchToken as ex:
            raise pkcs11.NoSuchToken(f"{self.token}: Token not found.") from ex
        except pkcs11.SessionReadOnly as ex:
            # E.g. trying to generate a key with a read-only session. Should not happen.
            raise pkcs11.SessionReadOnly("Attempting to write to a read-only session.") from ex
        except pkcs11.PKCS11Error as ex:
            # Catch-all for any PKCS11 error. Should not happen, as all relevant errors are handled above.
            raise pkcs11.PKCS11Error(f"Unknown pkcs11 error ({type(ex).__name__}).") from ex

    def _create_private_key(
        self,
        session: Session,
        key_id: str,
        key_label: str,
        key_type: ParsableKeyType,
        key_size: Optional[int],
        elliptic_curve: Optional[EllipticCurves],
    ) -> PKCS11PrivateKeyTypes:
        # Test that no private key with the given label exists. Some libraries (e.g. SoftHSM) don't treat the
        # label as unique and will silently create a second key with the same label.
        # NOTE: Using a rw session here, even though we don't need it. pkcs11 fails (at least with softhsm2)
        #   if an so_pin is used and a read-only session is requested. Also, we have to use rw when creating
        #   the key anyway.
        try:
            session.get_key(object_class=ObjectClass.PUBLIC_KEY, label=key_label)
        except pkcs11.NoSuchKey:
            pass  # this is what we hope for
        else:
            raise ValueError(f"{key_label}: Private key with this label already exists.")

        if key_type == "RSA":
            pkcs11_public_key, pkcs11_private_key = session.generate_keypair(
                pkcs11.KeyType.RSA, key_size, id=key_id.encode(), label=key_label, store=True
            )

            private_key: PKCS11PrivateKeyTypes = PKCS11RSAPrivateKey(
                session=session,
                key_id=key_id,
                key_label=key_label,
                pkcs11_private_key=pkcs11_private_key,
                pkcs11_public_key=pkcs11_public_key,
            )

        elif key_type in ("Ed25519", "Ed448"):
            named_curve_parameters = encode_named_curve_parameters(
                SignedDigestAlgorithmId(key_type.lower()).dotted
            )

            parameters = session.create_domain_parameters(
                KeyType.EC_EDWARDS, {pkcs11.Attribute.EC_PARAMS: named_curve_parameters}, local=True
            )

            pkcs11_public_key, pkcs11_private_key = parameters.generate_keypair(
                mechanism=pkcs11.Mechanism.EC_EDWARDS_KEY_PAIR_GEN,
                store=True,
                id=key_id.encode(),
                label=key_label,
            )

            if key_type == "Ed25519":
                private_key = PKCS11Ed25519PrivateKey(
                    session=session,
                    key_id=key_id,
                    key_label=key_label,
                    pkcs11_private_key=pkcs11_private_key,
                    pkcs11_public_key=pkcs11_public_key,
                )
            else:
                private_key = PKCS11Ed448PrivateKey(
                    session=session,
                    key_id=key_id,
                    key_label=key_label,
                    pkcs11_private_key=pkcs11_private_key,
                    pkcs11_public_key=pkcs11_public_key,
                )

        elif key_type == "EC":
            # TYPEHINT NOTE: elliptic curve is always set if key_type is EC.
            elliptic_curve_name = elliptic_curve.lower()  # type: ignore[union-attr]
            parameters = session.create_domain_parameters(
                KeyType.EC,
                {pkcs11.Attribute.EC_PARAMS: encode_named_curve_parameters(elliptic_curve_name)},
                local=True,
            )

            pkcs11_public_key, pkcs11_private_key = parameters.generate_keypair(
                store=True, id=key_id.encode(), label=key_label
            )

            private_key = PKCS11EllipticCurvePrivateKey(
                session=session,
                key_id=key_id,
                key_label=key_label,
                pkcs11_private_key=pkcs11_private_key,
                pkcs11_public_key=pkcs11_public_key,
            )
        else:
            raise ValueError(f"{key_type}: unknown key type")

        return private_key
