# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not,
# see <http://www.gnu.org/licenses/>.

"""Deprecation classes in django-ca."""

import functools
import typing
import warnings
from inspect import signature

F = typing.TypeVar("F", bound=typing.Callable[..., typing.Any])


class RemovedInDjangoCA123Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca==1.23."""

    version = "1.23"


class RemovedInDjangoCA124Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca==1.24."""

    version = "1.24"


class RemovedInDjangoCA125Warning(PendingDeprecationWarning):
    """Warning if a feature will be removed in django-ca==1.25."""

    version = "1.25"


RemovedInNextVersionWarning = RemovedInDjangoCA123Warning

DeprecationWarningType = typing.Union[
    typing.Type[RemovedInDjangoCA123Warning],
    typing.Type[RemovedInDjangoCA124Warning],
    typing.Type[RemovedInDjangoCA125Warning],
]


def deprecate_argument(
    arg: str, category: DeprecationWarningType, stacklevel: int = 2
) -> typing.Callable[[F], F]:
    """Decorator to mark an argument as deprecated.

    The decorator will issue a warning if the argument is passed to the decorated function, regardless of how
    the argument is passed.
    """

    def decorator_deprecate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            sig = signature(func)
            bound = sig.bind(*args, **kwargs)
            if arg in bound.arguments:
                warnings.warn(
                    f"Argument {arg} is deprecated and will be removed in django ca {category.version}.",
                    category=category,
                    stacklevel=stacklevel,
                )

            return func(*args, **kwargs)

        return typing.cast(F, wrapper)

    return decorator_deprecate


def deprecate_type(
    arg: str,
    types: typing.Union[typing.Type[typing.Any], typing.Tuple[typing.Type[typing.Any], ...]],
    category: DeprecationWarningType,
    stacklevel: int = 2,
) -> typing.Callable[[F], F]:
    """Decorator to mark a type for an argument as deprecated."""

    def decorator_deprecate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
            sig = signature(func)
            bound = sig.bind(*args, **kwargs)
            if arg in bound.arguments and isinstance(bound.arguments.get(arg), types):
                name = type(bound.arguments.get(arg)).__name__
                warnings.warn(
                    f"Passing {name} for {arg} is deprecated and will be removed in django ca {category.version}.",  # NOQA: E501
                    category=category,
                    stacklevel=stacklevel,
                )

            return func(*args, **kwargs)

        return typing.cast(F, wrapper)

    return decorator_deprecate
