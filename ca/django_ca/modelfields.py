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

"""django-ca model fields.

.. seealso:: https://docs.djangoproject.com/en/dev/howto/custom-model-fields/
"""

import typing

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django.db import models

from .fields import CertificateSigningRequestField as CertificateSigningRequestFormField

DecodableCertificateSigningRequest = typing.Union[str, bytes, x509.CertificateSigningRequest]

if typing.TYPE_CHECKING:
    BinaryFieldBase = models.BinaryField[DecodableCertificateSigningRequest, bytes]
else:
    BinaryFieldBase = models.BinaryField


class LazyCertificateSigningRequest:
    """Lazily parsed Certificate Signing Request.

    This class exists to avoid parsing a CSR into memory every time a model is accessed.
    """

    _bytes: bytes
    _csr: typing.Optional[x509.CertificateSigningRequest] = None

    def __init__(self, value: DecodableCertificateSigningRequest) -> None:
        if isinstance(value, str) and value.startswith("-----BEGIN CERTIFICATE REQUEST-----"):
            self._csr = x509.load_pem_x509_csr(value.encode())
            self._bytes = self._csr.public_bytes(Encoding.DER)
        elif isinstance(value, x509.CertificateSigningRequest):
            self._csr = value
            self._bytes = self._csr.public_bytes(Encoding.DER)
        elif isinstance(value, bytes):
            if value.startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
                self._csr = x509.load_pem_x509_csr(value)
                self._bytes = self._csr.public_bytes(Encoding.DER)
            else:
                self._bytes = value
        else:
            raise ValueError("%s: Could not parse Certificate Signing Request" % value)

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, LazyCertificateSigningRequest) and self._bytes == other._bytes

    def __repr__(self) -> str:
        return '<CertificateSigningRequest: %s>' % self.csr.subject.rfc4514_string()

    @property
    def csr(self) -> x509.CertificateSigningRequest:
        """This CSR as :py:class:`cg:cryptography.x509.CertificateSigningRequest`."""
        if self._csr is None:
            self._csr = x509.load_der_x509_csr(self._bytes)
        return self._csr

    @property
    def der(self) -> bytes:
        """This CSR as its raw DER representation."""
        return self._bytes

    @property
    def pem(self) -> str:
        """This CSR as str-encoded PEM."""
        return self.csr.public_bytes(Encoding.PEM).decode()


class CertificateSigningRequestField(BinaryFieldBase):
    """Django model field for CSRs."""

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        kwargs.setdefault("editable", True)
        kwargs.setdefault("null", True)
        super().__init__(*args, **kwargs)

    def deconstruct(self) -> typing.Tuple[str, str, typing.List[str], typing.Dict[str, str]]:
        """Used in migrations."""
        name, path, args, kwargs = super().deconstruct()

        if self.editable is True:
            del kwargs["editable"]
        if self.null is True:
            del kwargs["null"]

        return name, path, args, kwargs

    def formfield(self, **kwargs: typing.Any) -> CertificateSigningRequestFormField:
        """Customize the form field used by model forms."""
        defaults = {"form_class": CertificateSigningRequestFormField}
        defaults.update(kwargs)
        return super().formfield(**defaults)

    def from_db_value(  # pylint: disable=unused-argument
        self, value: typing.Optional[bytes], expression: typing.Any, condition: typing.Any
    ) -> typing.Optional[LazyCertificateSigningRequest]:
        """Called when data is loaded from the database.

        This is called when

        * a certificate is loaded from the database (``Certificate.objects.get()``, ...)
        * a queryset is used (*not* just creating it -> QS are lazy)
        """
        if value is None:
            return None
        return LazyCertificateSigningRequest(value)

    def get_prep_value(
        self,
        value: typing.Optional[
            typing.Union[LazyCertificateSigningRequest, DecodableCertificateSigningRequest]
        ],
    ) -> typing.Optional[bytes]:
        """Get the raw database value.

        This is called when

        * ``Certificate.save()`` is called
        * Also called for queryset methods when using a field of this type (e.g. ``.filter(csr=...)``).
        """
        if not value:
            return None
        if isinstance(value, LazyCertificateSigningRequest):
            return value.der
        return LazyCertificateSigningRequest(value).der

    def to_python(
        self,
        value: typing.Optional[
            typing.Union[LazyCertificateSigningRequest, DecodableCertificateSigningRequest]
        ],
    ) -> typing.Optional[LazyCertificateSigningRequest]:
        """Called during deserialization and during Certificate.full_clean()."""
        if not value:
            return None
        if isinstance(value, LazyCertificateSigningRequest):
            return value
        return LazyCertificateSigningRequest(value)
