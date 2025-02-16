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

"""Utility functions for HSMs."""

from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters

from asn1crypto.algos import SignedDigestAlgorithmId
from asn1crypto.core import OctetString
from asn1crypto.keys import PrivateKeyInfo, PublicKeyInfo


def decode_eddsa_private_key(der: bytes) -> dict[int, str | int | bytes]:
    """Decode a DER-encoded EdDSA private key into a dictionary for``pkcs11.Session.create_object``.

    This function was copied from
    https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/crypto.py.
    """
    asn1 = PrivateKeyInfo.load(der)
    return {
        Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.EC_PARAMS: encode_named_curve_parameters(SignedDigestAlgorithmId(asn1.algorithm).dotted),
        # Only the last 32/57 bytes is the private key values
        Attribute.VALUE: (
            asn1["private_key"].contents[-32:]
            if asn1.algorithm == "ed25519"
            else asn1["private_key"].contents[-57:]
        ),
    }


def decode_eddsa_public_key(der: bytes, encode_eddsa_point: bool = True) -> dict[int, str | int | bytes]:
    """Decode a DER-encoded EdDSA public key into a dictionary for``pkcs11.Session.create_object``.

    This function was copied from
    https://github.com/SUNET/python_x509_pkcs11/blob/main/src/python_x509_pkcs11/crypto.py.

    .. NOTE:: **encode_eddsa_point**
        For use as an attribute `EC_POINT` should be DER-encoded (True).
        For key derivation implementations can vary.  Since v2.30 the
        specification says implementations MUST accept a raw `EC_POINT` for
        ECDH (False), however not all implementations follow this yet.
    """
    asn1 = PublicKeyInfo.load(der)

    if asn1.algorithm not in ["ed25519", "ed448"]:  # pragma: no cover
        raise ValueError("Wrong algorithm, not an eddsa key!")

    ecpoint = bytes(asn1["public_key"])

    if encode_eddsa_point:  # pragma: no cover
        ecpoint = OctetString(ecpoint).dump()

    return {
        Attribute.KEY_TYPE: KeyType.EC_EDWARDS,
        Attribute.CLASS: ObjectClass.PUBLIC_KEY,
        Attribute.EC_PARAMS: encode_named_curve_parameters(SignedDigestAlgorithmId(asn1.algorithm).dotted),
        Attribute.EC_POINT: ecpoint,
    }
