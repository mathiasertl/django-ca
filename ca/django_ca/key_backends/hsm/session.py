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

"""Code for handling sessions for hardware security modules."""

import threading
from types import TracebackType
from typing import Final, Optional

import pkcs11
from pkcs11 import Session
from pkcs11._pkcs11 import lib as pkcs11_lib

PoolKeyType = tuple[str, str, Optional[str], Optional[str]]


class SessionPool:
    """Thread-safe session pool for PKCS11 sessions."""

    _lib_lock: Final[threading.Lock] = threading.Lock()
    _lib_pool: Final[dict[str, pkcs11_lib]] = {}

    _session_lock: Final[threading.Lock] = threading.Lock()
    _session_pool: Final[dict[PoolKeyType, Session]] = {}
    _session_refcount: Final[dict[PoolKeyType, int]] = {}

    path: Final[str]
    token_label: Final[str]
    so_pin: Final[Optional[str]]
    user_pin: Final[Optional[str]]
    rw: Final[bool]

    def __init__(
        self, path: str, token_label: str, so_pin: Optional[str], user_pin: Optional[str], rw: bool = False
    ) -> None:
        if so_pin is None and user_pin is None:
            raise ValueError("so_pin and user_pin cannot both be None.")
        if so_pin is not None and user_pin is not None:
            raise ValueError("Either so_pin and user_pin must be set.")

        self.path = path
        self.token_label = token_label
        self.so_pin = so_pin
        self.user_pin = user_pin
        self.rw = rw

    @classmethod
    def acquire(
        cls,
        path: str,
        token_label: str,
        so_pin: Optional[str] = None,
        user_pin: Optional[str] = None,
        rw: bool = False,
    ) -> Session:
        """Open a new session with the given parameters."""
        with cls._lib_lock:
            if path not in cls._lib_pool:
                cls._lib_pool[path] = pkcs11.lib(path)

        with cls._session_lock:
            pool_key = (path, token_label, so_pin, user_pin)
            if pool_key not in cls._session_pool:
                token = cls._lib_pool[path].get_token(token_label=token_label)
                cls._session_pool[pool_key] = token.open(rw=rw, so_pin=so_pin, user_pin=user_pin)
                cls._session_refcount[pool_key] = 1
            else:
                # Request a read/write session, but a read-only session is already present. According to the
                # PKCS11 documentation, some libraries don't allow multiple sessions for the same token per
                # process:
                #
                #   https://python-pkcs11.readthedocs.io/en/latest/concurrency.html
                #
                # Note that this does not happen in practice. A read/write session is only requested when
                # generating or importing keys, and this always runs on the command-line, where no other
                # session is ever present.
                if rw is True and cls._session_pool[pool_key].rw is False:
                    raise ValueError("Requested R/W session, but R/O session is already initialized.")

                cls._session_refcount[pool_key] += 1

            return cls._session_pool[pool_key]

    @classmethod
    def release(cls, path: str, token_label: str, so_pin: Optional[str], user_pin: Optional[str]) -> None:
        """Close session if no reference is known."""
        with cls._session_lock:
            pool_key = (path, token_label, so_pin, user_pin)
            cls._session_refcount[pool_key] -= 1

            if cls._session_refcount[pool_key] == 0:
                cls._session_pool[pool_key].close()
                del cls._session_pool[pool_key]
                del cls._session_refcount[pool_key]

                # If no session for this library is left open, reinitialize it
                if any(e for e in cls._session_pool if e[0] == path) is False:
                    cls._lib_pool[path].reinitialize()

    def __enter__(self) -> Session:
        return self.acquire(
            self.path, self.token_label, so_pin=self.so_pin, user_pin=self.user_pin, rw=self.rw
        )

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        self.release(self.path, self.token_label, so_pin=self.so_pin, user_pin=self.user_pin)
