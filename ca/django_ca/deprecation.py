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

"""Deprecation classes in django-ca."""

import functools
import warnings
from collections.abc import Callable
from inspect import signature
from typing import Any, TypeVar, cast

import josepy as jose
from acme.messages import Revocation

from cryptography import x509
from OpenSSL.crypto import X509, X509Req

from django_ca.acme.messages import CertificateRequest
from django_ca.constants import JOSEPY_VERSION

# IMPORTANT: Do **not** import any module from django_ca here, or you risk circular imports.

F = TypeVar("F", bound=Callable[..., Any])


class RemovedInDjangoCA240Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca~=2.4.0."""

    version = "2.4"


class RemovedInDjangoCA250Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca~=2.5.0."""

    version = "2.5"


class RemovedInDjangoCA260Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca~=2.6.0."""

    version = "2.6"


RemovedInNextVersionWarning = RemovedInDjangoCA240Warning

DeprecationWarningType = (
    type[RemovedInDjangoCA240Warning] | type[RemovedInDjangoCA250Warning] | type[RemovedInDjangoCA260Warning]
)


def deprecate_function(category: DeprecationWarningType, stacklevel: int = 2) -> Callable[[F], F]:
    """Decorator to deprecate an entire function."""

    def decorator_deprecate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            warnings.warn(
                f"{func.__name__}() is deprecated and will be removed in django-ca {category.version}.",
                category=category,
                stacklevel=stacklevel,
            )
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator_deprecate


def deprecate_argument(
    arg: str, category: DeprecationWarningType, stacklevel: int = 2, replacement: str | None = None
) -> Callable[[F], F]:
    """Decorator to mark an argument as deprecated.

    The decorator will issue a warning if the argument is passed to the decorated function, regardless of how
    the argument is passed.
    """
    message = f"Argument `{arg}` is deprecated and will be removed in django-ca {category.version}"
    if replacement is not None:  # pragma: no cover
        message += f", use `{replacement}` instead."
    else:
        message += "."

    def decorator_deprecate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sig = signature(func)
            bound = sig.bind(*args, **kwargs)
            if arg in bound.arguments:
                warnings.warn(message, category=category, stacklevel=stacklevel)

            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator_deprecate


def deprecate_type(
    arg: str,
    types: type[Any] | tuple[type[Any], ...],
    category: DeprecationWarningType,
    stacklevel: int = 2,
) -> Callable[[F], F]:
    """Decorator to mark a type for an argument as deprecated."""

    def decorator_deprecate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sig = signature(func)
            bound = sig.bind(*args, **kwargs)
            if arg in bound.arguments and isinstance(bound.arguments.get(arg), types):
                name = type(bound.arguments.get(arg)).__name__
                warnings.warn(
                    f"Passing {name} for {arg} is deprecated and will be removed in django-ca {category.version}.",  # NOQA: E501
                    category=category,
                    stacklevel=stacklevel,
                )

            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator_deprecate


def josepy_certificate_request(csr: x509.CertificateSigningRequest) -> CertificateRequest:
    """Wrapper function to get a CertificateRequest message."""
    if JOSEPY_VERSION >= (2, 0):  # pragma: only josepy>=2.0
        return CertificateRequest(csr=csr)
    return CertificateRequest(  # pragma: only josepy<2.0
        # pylint: disable-next=no-member
        csr=jose.util.ComparableX509(X509Req.from_cryptography(csr))  # type: ignore[attr-defined]
    )


def josepy_revocation(cert: CertificateRequest) -> Revocation:
    """Wrapper function to get a Revocation message."""
    if JOSEPY_VERSION >= (2, 0):  # pragma: josepy>=2.0 branch
        return Revocation(certificate=cert)
    return Revocation(  # pragma: only josepy<2.0
        # pylint: disable-next=no-member
        certificate=jose.util.ComparableX509(X509.from_cryptography(cert))  # type: ignore[attr-defined]
    )
