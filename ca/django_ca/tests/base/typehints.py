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

"""Shared typehints for tests."""

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, Protocol, TypedDict, TypeVar

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes

from django.db import DEFAULT_DB_ALIAS

from django_ca.models import DjangoCAModel

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser as User
    from django.test.client import _MonkeyPatchedWSGIResponse as HttpResponse
else:
    from django.contrib.auth import get_user_model
    from django.http import HttpResponse

    User = get_user_model()

DjangoCAModelTypeVar = TypeVar("DjangoCAModelTypeVar", bound=DjangoCAModel)


CertFixtureData = dict[str, Any]


class _OcspFixtureData(TypedDict):
    name: str
    filename: str


class OcspFixtureData(_OcspFixtureData, total=False):
    """Fixture data for OCSP requests.

    Keys:

    * name (str): name of the fixture
    * filename (str): name of the file of the stored request
    * nonce (str, optional): Nonce used in the request
    """

    nonce: str


class FixtureData(TypedDict):
    """Fixture data loaded/stored from JSON."""

    certs: dict[str, CertFixtureData]


class KeyDict(TypedDict):
    parsed: CertificateIssuerPrivateKeyTypes


class PubDict(TypedDict):
    pem: str
    parsed: x509.Certificate
    der: bytes


class CsrDict(TypedDict):
    parsed: x509.CertificateSigningRequest


class CaptureOnCommitCallbacks(Protocol):
    """Typehint for TestCase.captureOnCommitCallbacks()."""

    def __call__(
        self, using: str = DEFAULT_DB_ALIAS, execute: bool = False
    ) -> AbstractContextManager[list[Callable[..., Any]]]:  # pragma: no cover
        ...


__all__ = ["HttpResponse", "User"]
