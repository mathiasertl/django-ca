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
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""QuerySet classes for DjangoCA models."""

import abc
import typing
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.db.models import Q
from django.utils import timezone

from . import ca_settings
from .acme.constants import Status
from .typehints import Protocol, X509CertMixinTypeVar
from .utils import sanitize_serial

if not TYPE_CHECKING:
    # Inverting TYPE_CHECKING check here to make pylint==2.9.3 happy:
    #   https://github.com/PyCQA/pylint/issues/4697
    AcmeAccountQuerySetBase = (
        AcmeAuthorizationQuerySetBase
    ) = (
        AcmeCertificateQuerySetBase
    ) = (
        AcmeChallengeQuerySetBase
    ) = AcmeOrderQuerySetBase = CertificateQuerySetBase = CertificateAuthorityQuerySetBase = models.QuerySet

    QuerySetTypeVar = TypeVar("QuerySetTypeVar", bound=models.QuerySet)
else:  # pragma: no cover  # only used for type checking
    from .models import (
        AcmeAccount,
        AcmeAuthorization,
        AcmeCertificate,
        AcmeChallenge,
        AcmeOrder,
        Certificate,
        CertificateAuthority,
        X509CertMixin,
    )

    AcmeAccountQuerySetBase = models.QuerySet[AcmeAccount]
    AcmeAuthorizationQuerySetBase = models.QuerySet[AcmeAuthorization]
    AcmeCertificateQuerySetBase = models.QuerySet[AcmeCertificate]
    AcmeChallengeQuerySetBase = models.QuerySet[AcmeChallenge]
    AcmeOrderQuerySetBase = models.QuerySet[AcmeOrder]
    CertificateAuthorityQuerySetBase = models.QuerySet[CertificateAuthority]
    CertificateQuerySetBase = models.QuerySet[Certificate]

    QuerySetTypeVar = TypeVar("QuerySetTypeVar", bound=models.QuerySet[X509CertMixin])


class QuerySetProtocol(
    Protocol[X509CertMixinTypeVar]
):  # pragma: nocover; pylint: disable=missing-function-docstring
    """Protocol used for a generic-self in mixins.

    Note that I couldn't get this to work in functions that should return the same type as well. So::

        def filter(self: QuerySetProtocol) -> QuerySetProtocol:
            ...

    ... doesn't work, unfortunately.

    .. seealso:: https://mypy.readthedocs.io/en/latest/more_types.html#mixin-classes
    """

    model: X509CertMixinTypeVar

    def get(self, *args: Any, **kwargs: Any) -> X509CertMixinTypeVar:
        ...


class DjangoCAMixin(Generic[X509CertMixinTypeVar], metaclass=abc.ABCMeta):
    """Mixin with common methods for CertificateAuthority and Certificate models."""

    def get_by_serial_or_cn(
        self: QuerySetProtocol[X509CertMixinTypeVar], identifier: str
    ) -> X509CertMixinTypeVar:
        """Get a model by serial *or* by common name.

        This method is meant to get a CA from a user input value. If `identifier` is a serial, colons (``:``)
        and leading zeros are ignored. If no exact match is found it will search for CAs starting with that
        value. For example, if a CA has the serial ``ABCDE``, it will be found with "ABCDE", "A:BC:DE",
        "0A:BC:DE" or just "0AB" as `identifier`.
        """
        identifier = identifier.strip()
        exact_query = startswith_query = Q(cn=identifier)

        try:
            serial = sanitize_serial(identifier)
            exact_query |= Q(serial=serial)
            startswith_query |= Q(serial__startswith=serial)
        except ValueError:
            pass

        try:
            # Imported CAs might have a shorter serial and there is a chance that it might become impossible
            # to select a CA by serial if its serial matches another CA with a longer serial. So we try to
            # match by exact serial first.
            return self.get(exact_query)
        except self.model.DoesNotExist:
            return self.get(startswith_query)


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

        if ca_settings.CA_DEFAULT_CA:
            now = timezone.now()

            try:
                # NOTE: Don't prefilter queryset so that we can provide more specialized error messages below.
                ca = self.get(serial=ca_settings.CA_DEFAULT_CA)
            except self.model.DoesNotExist:
                # pylint: disable=raise-missing-from; not useful here
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {ca_settings.CA_DEFAULT_CA}: CA not found.")

            if ca.enabled is False:
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {ca_settings.CA_DEFAULT_CA} is disabled.")
            if ca.expires < now:
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {ca_settings.CA_DEFAULT_CA} is expired.")
            if ca.valid_from > now:  # OK, how could this ever happen? ;-)
                raise ImproperlyConfigured(f"CA_DEFAULT_CA: {ca_settings.CA_DEFAULT_CA} is not yet valid.")
            return ca

        # NOTE: We add the serial to sorting make *sure* we have deterministic behavior. In many cases, users
        # will just create several CAs that all actually expire on the same day.
        first_ca = self.usable().order_by("-expires", "serial").first()  # usable == enabled and valid
        if first_ca is None:
            raise ImproperlyConfigured("No CA is currently usable.")
        return first_ca

    def disabled(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are disabled."""
        return self.filter(enabled=False)

    def enabled(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are enabled."""
        return self.filter(enabled=True)

    def valid(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are currently valid."""
        now = timezone.now()
        return self.filter(expires__gt=now, valid_from__lt=now)

    def invalid(self) -> "CertificateAuthorityQuerySet":
        """Return CAs that are either expired or not yet valid."""
        now = timezone.now()
        return self.exclude(expires__gt=now, valid_from__lt=now)

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
        return self.filter(expires__gt=now, valid_from__lt=now)

    def not_yet_valid(self) -> "CertificateQuerySet":
        """Return certificates that are not yet valid."""

        return self.filter(revoked=False, valid_from__gt=timezone.now())

    def valid(self) -> "CertificateQuerySet":
        """Return valid certificates."""

        return self.currently_valid().filter(revoked=False)

    def expired(self) -> "CertificateQuerySet":
        """Returns expired certificates.

        Note that this method does not return revoked certificates that would otherwise be expired.
        """
        return self.filter(revoked=False, expires__lt=timezone.now())

    def revoked(self) -> "CertificateQuerySet":
        """Return revoked certificates."""

        return self.filter(revoked=True)


class AcmeAccountQuerySet(AcmeAccountQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeAccount`."""

    def viewable(self) -> "AcmeAccountQuerySet":
        """Filter ACME accounts that can be viewed via the ACME API.

        An account is considered viewable if the associated CA is usable. Note that an account is *viewable*
        also if it was revoked by the CA.
        """
        now = timezone.now()
        return self.filter(
            ca__enabled=True, ca__acme_enabled=True, ca__expires__gt=now, ca__valid_from__lt=now
        )


class AcmeOrderQuerySet(AcmeOrderQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeOrder`."""

    def account(self, account: "AcmeAccount") -> "AcmeOrderQuerySet":
        """Filter orders belonging to the given account."""
        return self.filter(account=account)

    def viewable(self) -> "AcmeOrderQuerySet":
        """Filter ACME orders that can be viewed via the ACME API.

        An order is considered viewable if the associated CA is usable and the account is not revoked.
        """
        now = timezone.now()
        return self.filter(
            account__ca__enabled=True,
            account__ca__acme_enabled=True,
            account__ca__expires__gt=now,
            account__ca__valid_from__lt=now,
        ).exclude(account__status=Status.REVOKED.value)


class AcmeAuthorizationQuerySet(AcmeAuthorizationQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeAuthorization`."""

    def account(self, account: "AcmeAccount") -> "AcmeAuthorizationQuerySet":
        """Filter authorizations belonging to the given account."""
        return self.filter(order__account=account)

    def dns(self) -> "AcmeAuthorizationQuerySet":
        """Get all authorizations of type DNS."""
        return self.filter(type=self.model.TYPE_DNS)

    def names(self) -> typing.List[str]:
        """Get a flat list of names identified by the current queryset."""
        return list(self.values_list("value", flat=True))

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
            order__account__ca__expires__gt=now,
            order__account__ca__valid_from__lt=now,
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
            auth__order__account__ca__expires__gt=now,
            auth__order__account__ca__valid_from__lt=now,
        ).exclude(auth__order__account__status=Status.REVOKED.value)


class AcmeCertificateQuerySet(AcmeCertificateQuerySetBase):
    """QuerySet for :py:class:`~django_ca.models.AcmeCertificate`."""

    def account(self, account: "AcmeAccount") -> "AcmeCertificateQuerySet":
        """Filter certificates belonging to the given account."""
        return self.filter(order__account=account)

    def url(self) -> "AcmeCertificateQuerySet":
        """Prepare queryset to get the ACME URL of objects without subsequent database lookups."""
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
                order__account__ca__expires__gt=now,
                order__account__ca__valid_from__lt=now,
                order__status=Status.VALID.value,
            )
            .exclude(order__account__status=Status.REVOKED.value)
            .exclude(cert__isnull=True)
            .exclude(cert__revoked=True)
        )
