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

"""Test ec classes."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import pytest

from django_ca.pydantic.ec import ECDSAModel
from django_ca.tests.pydantic.base import assert_cryptography_model


@pytest.mark.parametrize("algorithm", (hashes.SHA256(), hashes.SHA3_512()))
@pytest.mark.parametrize("deterministic_signing", (True, False))
def test_ecdsamodel(algorithm: hashes.HashAlgorithm, deterministic_signing: bool) -> None:
    """Test ECDSAModel."""
    parameters = {"algorithm": algorithm, "deterministic_signing": deterministic_signing}
    expected = ec.ECDSA(algorithm=algorithm, deterministic_signing=deterministic_signing)
    model = assert_cryptography_model(ECDSAModel, parameters, expected, has_equality=False)
    assert isinstance(model, ECDSAModel)
    assert model.cryptography.deterministic_signing == deterministic_signing
    assert isinstance(model.cryptography.algorithm, type(algorithm))
