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
import typing
import warnings
from inspect import signature
from typing import Any, Union

# IMPORTANT: Do **not** import any module from django_ca here, or you risk circular imports.

F = typing.TypeVar("F", bound=typing.Callable[..., Any])


class RemovedInDjangoCA210Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca~=2.1.0."""

    version = "2.1"


class RemovedInDjangoCA220Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca~=2.2.0."""

    version = "2.2"


class RemovedInDjangoCA230Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca~=2.3.0."""

    version = "2.3"


RemovedInNextVersionWarning = RemovedInDjangoCA210Warning

DeprecationWarningType = Union[
    type[RemovedInDjangoCA210Warning],
    type[RemovedInDjangoCA220Warning],
    type[RemovedInDjangoCA230Warning],
]


def deprecate_function(category: DeprecationWarningType, stacklevel: int = 2) -> typing.Callable[[F], F]:
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

        return typing.cast(F, wrapper)

    return decorator_deprecate


def deprecate_argument(
    arg: str, category: DeprecationWarningType, stacklevel: int = 2
) -> typing.Callable[[F], F]:
    """Decorator to mark an argument as deprecated.

    The decorator will issue a warning if the argument is passed to the decorated function, regardless of how
    the argument is passed.
    """

    def decorator_deprecate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sig = signature(func)
            bound = sig.bind(*args, **kwargs)
            if arg in bound.arguments:
                warnings.warn(
                    f"Argument {arg} is deprecated and will be removed in django-ca {category.version}.",
                    category=category,
                    stacklevel=stacklevel,
                )

            return func(*args, **kwargs)

        return typing.cast(F, wrapper)

    return decorator_deprecate


def deprecate_type(
    arg: str,
    types: Union[type[Any], tuple[type[Any], ...]],
    category: DeprecationWarningType,
    stacklevel: int = 2,
) -> typing.Callable[[F], F]:
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

        return typing.cast(F, wrapper)

    return decorator_deprecate
