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

"""Tests for :py:class:`django_ca.models.AcmeOrder`."""

from acme import messages

import pytest

from django_ca.models import AcmeOrder

pytestmark = pytest.mark.django_db


def test_error_defaults_to_none(acme_order: AcmeOrder) -> None:
    """Test that the error field is None for a newly created order."""
    assert acme_order.error is None
    assert acme_order.get_error() is None


def test_get_error(acme_order: AcmeOrder) -> None:
    """Test storing and retrieving an error."""
    error = messages.Error.with_code("badCSR", detail="The CSR is not acceptable.")
    acme_order.error = error.to_json()
    acme_order.status = AcmeOrder.STATUS_INVALID
    acme_order.save()

    order = AcmeOrder.objects.get(pk=acme_order.pk)
    assert order.get_error() == error
    assert order.get_error().code == "badCSR"  # type: ignore[union-attr]
    assert order.get_error().detail == "The CSR is not acceptable."  # type: ignore[union-attr]


def test_get_error_with_identifier_and_subproblems(acme_order: AcmeOrder) -> None:
    """Test that nested error fields survive the round trip to the database."""
    error = messages.Error.with_code(
        "compound",
        subproblems=(
            messages.Error.with_code(
                "dns", identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com")
            ),
            messages.Error.with_code(
                "caa", identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.net")
            ),
        ),
    )
    acme_order.error = error.to_json()
    acme_order.save()

    acme_order.refresh_from_db()
    stored = acme_order.get_error()
    assert stored == error
    assert [subproblem.code for subproblem in stored.subproblems] == ["dns", "caa"]  # type: ignore[union-attr]
    assert stored.subproblems[0].identifier.value == "example.com"  # type: ignore[union-attr,index]


def test_get_error_can_be_cleared(acme_order: AcmeOrder) -> None:
    """Test that an error can be reset to None again."""
    acme_order.error = messages.Error.with_code("serverInternal").to_json()
    acme_order.save()
    acme_order.refresh_from_db()
    assert acme_order.get_error() is not None

    acme_order.error = None
    acme_order.save()
    acme_order.refresh_from_db()
    assert acme_order.error is None
    assert acme_order.get_error() is None


def test_set_error(acme_order: AcmeOrder) -> None:
    """Test the set_error() method with only a code."""
    acme_order.set_error("badCSR")
    acme_order.save()

    order = AcmeOrder.objects.get(pk=acme_order.pk)
    assert order.error == {"type": "urn:ietf:params:acme:error:badCSR"}
    assert order.get_error() == messages.Error.with_code("badCSR")


def test_set_error_with_detail_and_identifier(acme_order: AcmeOrder) -> None:
    """Test the set_error() method with all scalar parameters."""
    identifier = messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com")
    acme_order.set_error("rejectedIdentifier", detail="Identifier is blocked.", identifier=identifier)
    acme_order.save()

    acme_order.refresh_from_db()
    assert acme_order.error == {
        "type": "urn:ietf:params:acme:error:rejectedIdentifier",
        "detail": "Identifier is blocked.",
        "identifier": {"type": "dns", "value": "example.com"},
    }

    stored = acme_order.get_error()
    assert stored is not None
    assert stored.code == "rejectedIdentifier"
    assert stored.detail == "Identifier is blocked."
    assert stored.identifier == identifier


def test_set_error_with_subproblems(acme_order: AcmeOrder) -> None:
    """Test the set_error() method with subproblems."""
    subproblems = [
        messages.Error.with_code(
            "dns", identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.com")
        ),
        messages.Error.with_code(
            "caa", identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="example.net")
        ),
    ]
    acme_order.set_error("compound", subproblems=subproblems)
    acme_order.save()

    acme_order.refresh_from_db()
    stored = acme_order.get_error()
    assert stored == messages.Error.with_code("compound", subproblems=tuple(subproblems))
    assert [subproblem.code for subproblem in stored.subproblems] == ["dns", "caa"]  # type: ignore[union-attr]


def test_set_error_does_not_save(acme_order: AcmeOrder) -> None:
    """Test that set_error() only updates the instance, but does not write to the database."""
    acme_order.set_error("serverInternal")
    assert acme_order.get_error() == messages.Error.with_code("serverInternal")

    # The database is not updated yet.
    assert AcmeOrder.objects.get(pk=acme_order.pk).error is None

    # ... so the status can be stored with the same write.
    acme_order.status = AcmeOrder.STATUS_INVALID
    acme_order.save()

    acme_order.refresh_from_db()
    assert acme_order.status == AcmeOrder.STATUS_INVALID
    assert acme_order.get_error() == messages.Error.with_code("serverInternal")


def test_set_error_with_unknown_code(acme_order: AcmeOrder) -> None:
    """Test that an unknown ACME error code is rejected."""
    with pytest.raises(ValueError, match=r"^wrong: Invalid error code\.$"):
        acme_order.set_error("wrong")

    assert acme_order.error is None
    assert acme_order.get_error() is None
