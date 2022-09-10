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

"""Some sanitity tests for constants."""

from cryptography import x509

from django.test import TestCase

from ..constants import ReasonFlags


class ReasonFlagsTestCase(TestCase):
    """Test readon flags."""

    def test_completeness(self) -> None:
        """Test that our list completely mirrors the cryptography list."""
        self.assertEqual(
            list(sorted([(k, v.value) for k, v in ReasonFlags.__members__.items()])),
            list(sorted([(k, v.value) for k, v in x509.ReasonFlags.__members__.items()])),
        )
