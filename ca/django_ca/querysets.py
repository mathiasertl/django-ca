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

"""QuerySet classes for DjangoCA models."""

import abc
import typing
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Generic, Optional, TypeVar

from cryptography import x509

from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.db.models import Q, QuerySet
from django.utils import timezone

from django_ca.acme.constants import Status
from django_ca.conf import model_settings
from django_ca.typehints import X509CertMixinTypeVar
from django_ca.utils import sanitize_serial

if not TYPE_CHECKING:
    # Inverting TYPE_CHECKING check here to make pylint==2.9.3 happy:
    #   https://github.com/PyCQA/pylint/issues/4697
    CertificateQuerySetBase = CertificateAuthorityQuerySetBase = models.QuerySet
    CertificateRevocationListQuerySetBase = models.QuerySet
    AcmeAccountQuerySetBase = AcmeAuthorizationQuerySetBase = AcmeCertificateQuerySetBase = (
        AcmeChallengeQuerySetBase
    ) = AcmeOrderQuerySetBase = models.QuerySet

    QuerySetTypeVar = TypeVar("QuerySetTypeVar", bound=models.QuerySet)
else:  # pragma: no cover  # only used for type checking
    from typing import Self

    from django_ca.models import (
        AcmeAccount,
        AcmeAuthorization,
        AcmeCertificate,
        AcmeChallenge,
        AcmeOrder,
        Certificate,
        CertificateAuthority,
        CertificateRevocationList,
        X509CertMixin,
    )

    AcmeAccountQuerySetBase = models.QuerySet[AcmeAccount]
    AcmeAuthorizationQuerySetBase = models.QuerySet[AcmeAuthorization]
    AcmeCertificateQuerySetBase = models.QuerySet[AcmeCertificate]
    AcmeChallengeQuerySetBase = models.QuerySet[AcmeChallenge]
    AcmeOrderQuerySetBase = models.QuerySet[AcmeOrder]
    CertificateAuthorityQuerySetBase = models.QuerySet[CertificateAuthority]
    CertificateQuerySetBase = models.QuerySet[Certificate]
    CertificateRevocationListQuerySetBase = models.QuerySet[CertificateRevocationList]

    QuerySetTypeVar = TypeVar("QuerySetTypeVar", bound=models.QuerySet[X509CertMixin])


class X509CertMixinQuerySetProtocol(
    typing.Protocol[X509CertMixinTypeVar]
):  # pragma: nocover; pylint: disable=missing-function-docstring
    """Protocol used for a generic-self in mixins.

    Note that I couldn't get this to work in functions that should return the same type as well. So::

        def filter(self: X509CertMixinQuerySetProtocol) -> X509CertMixinQuerySetProtocol:
            ...

    ... doesn't work, unfortunately.

    .. seealso:: https://mypy.readthedocs.io/en/latest/more_types.html#mixin-classes
    """

    model: X509CertMixinTypeVar

    def filter(self, *args: Any, **kwargs: Any) -> "Self": ...

    def get(self, *args: Any, **kwargs: Any) -> X509CertMixinTypeVar: ...

    def _serial_or_cn_query(self, identifier: str) -> tuple[Q, Q]: ...

    def revoked(self) -> "Self": ...


class DjangoCAMixin(Generic[X509CertMixinTypeVar], metaclass=abc.ABCMeta):
    """Mixin with common methods for CertificateAuthority and Certificate models."""

    def _serial_or_cn_query(
        self: X509CertMixinQuerySetProtocol[X509CertMixinTypeVar], identifier: str
    ) -> tuple[Q, Q]:
        identifier = identifier.strip()
        exact_query = startswith_query = Q(cn=identifier)

        try:
            serial = sanitize_serial(identifier)
            exact_query |= Q(serial=serial)
            startswith_query |= Q(serial__startswith=serial)
        except ValueError:
            pass
        return exact_query, startswith_query

    def get_by_serial_or_cn(
        self: X509CertMixinQuerySetProtocol[X509CertMixinTypeVar], identifier: str
    ) -> X509CertMixinTypeVar:
        """Get a model by serial *or* by common name.

        This method is meant to get a CA from a user input value. If `identifier` is a serial, colons (``:``)
        and leading zeros are ignored. If no exact match is found it will search for CAs starting with that
        value. For example, if a CA has the serial ``ABCDE``, it will be found with "ABCDE", "A:BC:DE",
        "0A:BC:DE" or just "0AB" as `identifier`.
        """
        exact_query, startswith_query = self._serial_or_cn_query(identifier)

        try:
            # Imported CAs might have a shorter serial and there is a chance that it might become impossible
            # to select a CA by serial if its serial matches another CA with a longer serial. So we try to
            # match by exact serial first.
            return self.get(exact_query)
        except self.model.DoesNotExist:
            return self.get(startswith_query)

    def for_certificate_revocation_list(
        self: X509CertMixinQuerySetProtocol[X509CertMixinTypeVar],
        *,
        now: datetime,
        reasons: Optional[Iterable[x509.ReasonFlags]],
        grace_timedelta: timedelta = timedelta(minutes=10),
    ) -> X509CertMixinQuerySetProtocol[X509CertMixinTypeVar]:
        """Get certificates for a certificate revocation list (CRL).

        .. versionadded:: 2.1.0
        """
        # Include certificates expired up to 10 minutes ago to account for a potential clock skew by a client.
        not_before = now + grace_timedelta
        not_after = now - grace_timedelta

        qs = self.filter(not_before__lt=not_before, not_after__gt=not_after).revoked()

        if reasons is not None:
            reason_names = [reason.name for reason in reasons]
            qs = self.filter(revoked_reason__in=reason_names)
        return qs


class CertificateAuthorityQuerySet(DjangoCAMixin["CertificateAuthority"], CertificateAuthorityQuerySetBase):
    """QuerySet for the CertificateAuthority model."""

    def acme(self) -> "CertificateAuthorityQuerySet":
        """Return usable CAs that have support for the ACME protocol enabled."""
        return self.filter(acme_enabled=True)

    def default(self) -> "CertificateAuthority":
        """Return the default CA to use when no CA is selected.

        This function honors the :ref:`CA_DEFAULT_CA <settings-ca-default-ca>`. If no usable CA can be
        returned, raises :py:exc:`~django:django.core.exceptions.ImproperlyConfigured`.

        Raises
        ------
        :py:exc:`~django:django.core.exceptions.ImproperlyConfigured`
            When the CA named by :ref:`CA_DEFAULT_CA <settings-ca-default-ca>` is either not found, disabled
            or not currently valid. Or, if the setting is not set, no CA is currently usable.
        """
        if (serial := model_settings.CA_DEFAULT_CA) is not None:
            try:
                # NOTE: Don't prefilter queryset so that we can provide more specialized error messages below.
                ca = self.get(serial=serial)
            except self.model.DoesNotExist as ex:
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {serial}: CA not found.") from ex

            if ca.enabled is False:
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {serial} is disabled.")

            now = timezone.now()
            if ca.not_after < now:
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {serial} is expired.")
            if ca.not_before > now:  # OK, how could this ever happen? ;-)
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {serial} is not yet valid.")
            return ca

        # NOTE: We add the serial to sorting make *sure* we have deterministic behavior. In many cases, users
        # will just create several CAs that all actually expire on the same day.
        first_ca_qs = self.usable().order_by("-not_after", "serial")  # usable == enabled and valid
        first_ca = first_ca_qs.first()
        if first_ca is None:
            raise ImproperlyConfigured("No CA is currently usable.")
        return first_ca

    def disabled(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are disabled."""
        return self.filter(enabled=False)

    def enabled(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are enabled."""
        return self.filter(enabled=True)

    def preferred_order(self) -> "CertificateAuthorityQuerySet":
        """Return CAs in order of preference."""
        return self.order_by("-not_after", "serial")

    def valid(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are currently valid."""
        now = timezone.now()
        return self.filter(not_after__gt=now, not_before__lt=now)

    def invalid(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are either expired or not yet valid."""
        now = timezone.now()
        return self.exclude(not_after__gt=now, not_before__lt=now)

    def revoked(self) -> "CertificateAuthorityQuerySet":
        """Return revoked certificates."""
        return self.filter(revoked=True)

    def usable(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are enabled and currently valid."""
        return self.enabled().valid()


class CertificateQuerySet(DjangoCAMixin["Certificate"], CertificateQuerySetBase):
    """QuerySet for the Certificate model."""

    def currently_valid(self) -> "CertificateQuerySet":
        """Return certificates currently valid according to their not_before/not_after fields.

        .. WARNING:: This does not exclude revoked certificates.
        """
        now = timezone.now()
        return self.filter(not_after__gt=now, not_before__lt=now)

    def not_yet_valid(self) -> "CertificateQuerySet":
        """Return certificates that are not yet valid."""
        return self.filter(revoked=False, not_before__gt=timezone.now())

    def valid(self) -> "CertificateQuerySet":
        """Return valid certificates."""
        return self.currently_valid().filter(revoked=False)

    def expired(self) -> "CertificateQuerySet":
        """Returns expired certificates.

        Note that this method does not return revoked certificates that would otherwise be expired.
        """
        return self.filter(revoked=False, not_after__lt=timezone.now())

    def revoked(self) -> "CertificateQuerySet":
        """Return revoked certificates."""
        return self.filter(revoked=True)


class CertificateRevocationListQuerySet(CertificateRevocationListQuerySetBase):
    """Queryset for :class:`~django_ca.models.CertificateRevocationList`."""

    def newest(self) -> Optional["CertificateRevocationList"]:
        """Get the instance with the highest CRL number."""
        return self.order_by("-number").first()

    def reasons(
        self, only_some_reasons: Optional[frozenset[x509.ReasonFlags]]
    ) -> "CertificateRevocationListQuerySet":
        """Return CRLs with the given set of reasons."""
        if only_some_reasons is None:
            return self.filter(only_some_reasons__isnull=True)
        reason_names = [reason.name for reason in only_some_reasons]
        return self.filter(only_some_reasons=sorted(reason_names))

    def scope(
        self,
        serial: str,
        only_contains_ca_certs: bool = False,
        only_contains_user_certs: bool = False,
        only_contains_attribute_certs: bool = False,
        only_some_reasons: Optional[frozenset[x509.ReasonFlags]] = None,
    ) -> "CertificateRevocationListQuerySet":
        """Return CRLs with the given scope."""
        return self.filter(
            ca__serial=serial,
            only_contains_ca_certs=only_contains_ca_certs,
            only_contains_user_certs=only_contains_user_certs,
            only_contains_attribute_certs=only_contains_attribute_certs,
        ).reasons(only_some_reasons)


class AcmeAccountQuerySet(AcmeAccountQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeAccount`."""

    def url(self) -> "AcmeAccountQuerySet":
        """Assure that returned models can build an ACME URL without additional database queries."""
        return self.select_related("ca")

    def viewable(self) -> "AcmeAccountQuerySet":
        """Filter ACME accounts that can be viewed via the ACME API.

        An account is considered viewable if the associated CA is usable. Note that an account is *viewable*
        also if it was revoked by the CA.
        """
        now = timezone.now()
        return self.filter(
            ca__enabled=True, ca__acme_enabled=True, ca__not_after__gt=now, ca__not_before__lt=now
        )


class AcmeOrderQuerySet(AcmeOrderQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeOrder`."""

    def account(self, account: "AcmeAccount") -> "AcmeOrderQuerySet":
        """Filter orders belonging to the given account."""
        return self.filter(account=account)

    def url(self) -> "AcmeOrderQuerySet":
        """Assure that returned models can build an ACME URL without additional database queries."""
        return self.select_related("account__ca")

    def viewable(self) -> "AcmeOrderQuerySet":
        """Filter ACME orders that can be viewed via the ACME API.

        An order is considered viewable if the associated CA is usable and the account is not revoked.
        """
        now = timezone.now()
        return self.filter(
            account__ca__enabled=True,
            account__ca__acme_enabled=True,
            account__ca__not_after__gt=now,
            account__ca__not_before__lt=now,
        ).exclude(account__status=Status.REVOKED.value)


class AcmeAuthorizationQuerySet(AcmeAuthorizationQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeAuthorization`."""

    def account(self, account: "AcmeAccount") -> "AcmeAuthorizationQuerySet":
        """Filter authorizations belonging to the given account."""
        return self.filter(order__account=account)

    def dns(self) -> "AcmeAuthorizationQuerySet":
        """Get all authorizations of type DNS."""
        return self.filter(type=self.model.TYPE_DNS)

    def names(self) -> QuerySet["AcmeAuthorization", str]:
        """Get a flat list of names identified by the current queryset."""
        return self.values_list("value", flat=True)

    def url(self) -> "AcmeAuthorizationQuerySet":
        """Prepare queryset to get the ACME URL of objects without subsequent database lookups."""
        return self.select_related("order__account__ca")

    def valid(self) -> "AcmeAuthorizationQuerySet":
        """Filter for currently valid authorizations."""
        return self.filter(order__expires__gt=timezone.now(), status=self.model.STATUS_VALID)

    def viewable(self) -> "AcmeAuthorizationQuerySet":
        """Filter ACME authzs that can be viewed via the ACME API.

        An authz is considered viewable if the associated CA is usable and the account is not revoked.
        """
        now = timezone.now()
        return self.filter(
            order__account__ca__enabled=True,
            order__account__ca__acme_enabled=True,
            order__account__ca__not_after__gt=now,
            order__account__ca__not_before__lt=now,
        ).exclude(order__account__status=Status.REVOKED.value)


class AcmeChallengeQuerySet(AcmeChallengeQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeChallenge`."""

    def account(self, account: "AcmeAccount") -> "AcmeChallengeQuerySet":
        """Filter challenges belonging to the given account."""
        return self.filter(auth__order__account=account)

    def url(self) -> "AcmeChallengeQuerySet":
        """Prepare queryset to get the ACME URL of objects without subsequent database lookups."""
        return self.select_related("auth__order__account__ca")

    def viewable(self) -> "AcmeChallengeQuerySet":
        """Filter ACME challenges that can be viewed via the ACME API.

        An authz is considered viewable if the associated CA is usable and the account is not revoked.
        """
        now = timezone.now()
        return self.filter(
            auth__order__account__ca__enabled=True,
            auth__order__account__ca__acme_enabled=True,
            auth__order__account__ca__not_after__gt=now,
            auth__order__account__ca__not_before__lt=now,
        ).exclude(auth__order__account__status=Status.REVOKED.value)


class AcmeCertificateQuerySet(AcmeCertificateQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeCertificate`."""

    def account(self, account: "AcmeAccount") -> "AcmeCertificateQuerySet":
        """Filter certificates belonging to the given account."""
        return self.filter(order__account=account)

    def url(self) -> "AcmeCertificateQuerySet":
        """Assure that returned models can build an ACME URL without additional database queries."""
        return self.select_related("order__account__ca")

    def viewable(self) -> "AcmeCertificateQuerySet":
        """Filter ACME certificates that can be viewed via the ACME API.

        An authz is considered viewable if the associated CA is usable, the order is ready, the account is not
        revoked and the certificate itself was not revoked.
        """
        now = timezone.now()
        return (
            self.filter(
                order__account__ca__enabled=True,
                order__account__ca__acme_enabled=True,
                order__account__ca__not_after__gt=now,
                order__account__ca__not_before__lt=now,
                order__status=Status.VALID.value,
            )
            .exclude(order__account__status=Status.REVOKED.value)
            .exclude(cert__isnull=True)
            .exclude(cert__revoked=True)
        )
