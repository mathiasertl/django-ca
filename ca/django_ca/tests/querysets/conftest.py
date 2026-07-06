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

"""Test setup for queryset tests."""

import abc
from datetime import timedelta
from typing import Generic, TypeVar

from django.utils import timezone

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.models import Certificate, CertificateAuthority
from django_ca.querysets import CertificateAuthorityQuerySet, CertificateQuerySet
from django_ca.tests.base.constants import TIMESTAMPS

ModelTypeVar = TypeVar("ModelTypeVar", CertificateAuthority, Certificate)
QuerySetTypeVar = TypeVar("QuerySetTypeVar", CertificateAuthorityQuerySet, CertificateQuerySet)


class X509CertMixinQuerySetTestCaseBase(Generic[ModelTypeVar, QuerySetTypeVar], metaclass=abc.ABCMeta):
    """Tests common to querysets for CertificateAuthority and Certificate."""

    model: type[ModelTypeVar]

    @pytest.fixture
    def queryset(self) -> QuerySetTypeVar:
        """Fixture for the QuerySet."""
        return self.model.objects.all()  # type: ignore[return-value]

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    def test_current(self, obj: ModelTypeVar, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.current`."""
        assert list(queryset.current()) == [obj]

    @pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
    @pytest.mark.usefixtures("obj")
    def test_current_after_expiry(self, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.current` after everything expired."""
        assert not list(queryset.current())

    @pytest.mark.freeze_time(TIMESTAMPS["before_cas"])
    @pytest.mark.usefixtures("obj")
    def test_current_before_valid(self, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.current` before anything is valid."""
        assert not list(queryset.current())

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    @pytest.mark.usefixtures("obj")
    def test_current_with_now(self, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.current` with now parameter."""
        assert not list(queryset.current(now=TIMESTAMPS["before_cas"]))
        assert not list(queryset.current(now=TIMESTAMPS["everything_expired"]))

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    @pytest.mark.usefixtures("obj")
    def test_expired(self, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.expired`."""
        assert not list(queryset.expired())

    @pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
    def test_expired_after_expiry(self, obj: ModelTypeVar, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.expired` after everything expired."""
        assert list(queryset.expired()) == [obj]

    @pytest.mark.freeze_time(TIMESTAMPS["before_cas"])
    @pytest.mark.usefixtures("obj")
    def test_expired_before_valid(self, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.expired` before anything is valid."""
        assert not list(queryset.expired())

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    def test_expired_with_now(self, obj: ModelTypeVar, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.expired` with now parameter."""
        assert not list(queryset.expired(now=TIMESTAMPS["before_cas"]))
        assert list(queryset.expired(now=TIMESTAMPS["everything_expired"])) == [obj]

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    @pytest.mark.requires_ca("child")
    def test_for_ocsp_cache(self, obj: ModelTypeVar, queryset: QuerySetTypeVar) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.for_ocsp_cache`."""
        assert list(queryset.for_ocsp_cache()) == [obj]

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    def test_for_ocsp_cache_with_valid_entry(
        self, settings: SettingsWrapper, obj: ModelTypeVar, queryset: QuerySetTypeVar
    ) -> None:
        """Test :py:func:`~django_ca.querysets.X509CertMixinQuerySet.for_ocsp_cache` with a valid entry."""
        settings.CA_OCSP_RESPONSE_CACHE_RENEWAL = timedelta(days=1)
        obj.ocsp_response_expires = timezone.now() + timedelta(days=100)
        obj.save()
        assert not list(queryset.for_ocsp_cache())

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    @pytest.mark.requires_ca("child")
    def test_for_ocsp_cache_with_renewal_entry(
        self, settings: SettingsWrapper, obj: ModelTypeVar, queryset: QuerySetTypeVar
    ) -> None:
        """Test `for_ocsp_cache` with an entry scheduled for removal."""
        settings.CA_OCSP_RESPONSE_CACHE_RENEWAL = timedelta(days=1)
        obj.ocsp_response_expires = timezone.now() + timedelta(seconds=10)
        obj.save()
        assert list(queryset.for_ocsp_cache()) == [obj]

    @pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
    @pytest.mark.usefixtures("obj")
    def test_for_ocsp_cache_after_expiry(self, queryset: QuerySetTypeVar) -> None:
        """Test `for_ocsp_cache` after everything is expired."""
        assert not list(queryset.for_ocsp_cache())

    @pytest.mark.freeze_time(TIMESTAMPS["before_cas"])
    @pytest.mark.usefixtures("obj")
    def test_for_ocsp_cache_before_valid(self, queryset: QuerySetTypeVar) -> None:
        """Test `for_ocsp_cache` before anything is valid."""
        assert not list(queryset.for_ocsp_cache())

    @pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
    @pytest.mark.usefixtures("obj")
    def test_for_ocsp_cache_with_now(self, queryset: QuerySetTypeVar) -> None:
        """Test `for_ocsp_cache` with now parameter."""
        assert not list(queryset.for_ocsp_cache(now=TIMESTAMPS["before_cas"]))
        assert not list(queryset.for_ocsp_cache(now=TIMESTAMPS["everything_expired"]))

    def test_revoked(self, obj: ModelTypeVar, queryset: QuerySetTypeVar) -> None:
        """Test the :py:func:`~django_ca.querysets.X509CertMixinQuerySet.revoked`."""
        assert obj.revoked is False
        assert not list(queryset.revoked())

        obj.revoked = True
        obj.save()
        assert list(queryset.revoked()) == [obj]
