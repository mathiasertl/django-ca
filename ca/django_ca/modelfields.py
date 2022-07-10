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

import abc
import typing

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from django import forms
from django.db import models

from .fields import CertificateSigningRequestField as CertificateSigningRequestFormField

DecodableCertificate = typing.Union[str, bytes, x509.Certificate]
DecodableCertificateSigningRequest = typing.Union[str, bytes, x509.CertificateSigningRequest]
LoadedTypeVar = typing.TypeVar("LoadedTypeVar", x509.CertificateSigningRequest, x509.Certificate)
DecodableTypeVar = typing.TypeVar(
    "DecodableTypeVar", DecodableCertificate, DecodableCertificateSigningRequest
)
# TYPE NOTE: mypy does not support using generics as bound ("bound=LazyField[DecodableTypeVar, ...]").
#   If we list concrete subclasses instead, typing functions that take DecodableTypeVar and return a
#   WrapperTypeVar instance becomes difficult, as mypy has no way of knowing that DecodableTypeVar argument
#   matches the type in required by the constructor of WrapperTypeVar.
WrapperTypeVar = typing.TypeVar("WrapperTypeVar", bound="LazyField")  # type: ignore[type-arg]

# mypy-django makes modelfields a generic class, so we need  a different base when type checking.
if typing.TYPE_CHECKING:

    class LazyBinaryFieldBase(
        models.BinaryField[typing.Union[DecodableTypeVar, WrapperTypeVar], WrapperTypeVar],
        typing.Generic[DecodableTypeVar, WrapperTypeVar],
    ):
        # pylint: disable=missing-class-docstring
        pass

else:

    class LazyBinaryFieldBase(models.BinaryField, typing.Generic[DecodableTypeVar, WrapperTypeVar]):
        # pylint: disable=missing-class-docstring
        pass


class LazyField(typing.Generic[LoadedTypeVar, DecodableTypeVar], metaclass=abc.ABCMeta):
    """Abstract base class for lazy field values.

    Subclasses of this class can be used by *binary* modelfields to load a cryptography value when first
    accessed.
    """

    _bytes: bytes
    _loaded: typing.Optional[LoadedTypeVar] = None
    _pem_token: typing.ClassVar[bytes]
    _type: typing.Type[LoadedTypeVar]

    def __init__(self, value: DecodableTypeVar) -> None:
        """Constructor must accept a decodable type var."""
        if isinstance(value, bytes):  # SQLite passes bytes
            if value.startswith(self._pem_token):
                self._loaded = self.load_pem(value)
                value = self._loaded.public_bytes(Encoding.DER)

            self._bytes = value
        elif isinstance(value, bytearray):
            self._bytes = bytes(value)
        elif isinstance(value, memoryview):  # PostgreSQL driver passes memoryview
            self._bytes = value.tobytes()
        elif isinstance(value, str):
            self._loaded = self.load_pem(value.encode())
            self._bytes = self._loaded.public_bytes(Encoding.DER)
        elif isinstance(value, self._type):
            self._loaded = value
            self._bytes = self._loaded.public_bytes(Encoding.DER)
        else:
            raise ValueError(f"{value}: Could not parse {self._type.__name__}")

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, self.__class__) and self._bytes == other._bytes

    def __repr__(self) -> str:
        name = self.__class__.__name__
        value = self.loaded.subject.rfc4514_string()
        return f"<{name}: {value}>"

    @abc.abstractmethod
    def load_pem(self, value: bytes) -> LoadedTypeVar:
        """Return the loaded value from the given bytes."""

    @property
    @abc.abstractmethod
    def loaded(self) -> LoadedTypeVar:
        """The stored value parsed into a cryptography object."""

    def encode(self, encoding: Encoding) -> bytes:
        """
        Parameters
        ----------

        encoding : attr of :py:class:`~cg:cryptography.hazmat.primitives.serialization.Encoding`, optional
            The format to return, defaults to ``Encoding.PEM``.
        """
        if encoding == Encoding.DER:
            return self._bytes
        return self.loaded.public_bytes(encoding)

    @property
    def der(self) -> bytes:
        """This field in its raw DER representation."""
        return self._bytes

    @property
    def pem(self) -> str:
        """This CSR as str-encoded PEM."""
        return self.loaded.public_bytes(Encoding.PEM).decode()


class LazyCertificateSigningRequest(
    LazyField[x509.CertificateSigningRequest, DecodableCertificateSigningRequest]
):
    """A lazy field for a :py:class:`~cg:cryptography.x509.CertificateSigningRequest."""

    _pem_token = b"-----BEGIN CERTIFICATE REQUEST-----"
    _type = x509.CertificateSigningRequest

    def load_pem(self, value: bytes) -> x509.CertificateSigningRequest:
        return x509.load_pem_x509_csr(value)

    @property
    def loaded(self) -> x509.CertificateSigningRequest:
        """This CSR as :py:class:`cg:cryptography.x509.CertificateSigningRequest`."""
        if self._loaded is None:
            self._loaded = x509.load_der_x509_csr(self._bytes)
        return self._loaded


class LazyCertificate(LazyField[x509.Certificate, DecodableCertificate]):
    """A lazy field for a :py:class:`~cg:cryptography.x509.Certificate."""

    _pem_token = b"-----BEGIN CERTIFICATE-----"
    _type = x509.Certificate

    def load_pem(self, value: bytes) -> x509.Certificate:
        return x509.load_pem_x509_certificate(value)

    @property
    def loaded(self) -> x509.Certificate:
        """This CSR as :py:class:`cg:cryptography.x509.CertificateSigningRequest`."""
        if self._loaded is None:
            self._loaded = x509.load_der_x509_certificate(self._bytes)
        return self._loaded


class LazyBinaryField(
    LazyBinaryFieldBase[DecodableTypeVar, WrapperTypeVar], typing.Generic[DecodableTypeVar, WrapperTypeVar]
):
    """Base class for binary modelfields that parse the value when first used."""

    formfield_class: typing.Type[forms.Field]
    wrapper: typing.Type[WrapperTypeVar]

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        kwargs.setdefault("editable", True)
        super().__init__(*args, **kwargs)

    def deconstruct(self) -> typing.Tuple[str, str, typing.List[str], typing.Dict[str, str]]:
        """Used in migrations."""
        name, path, args, kwargs = super().deconstruct()

        # COVERAGE NOTE: parent field sets this to False, so we override the default. But we don't actually
        #   need a non-editable field, so we never manually set this to False.
        if self.editable is True:  # pragma: no branch
            del kwargs["editable"]

        return name, path, args, kwargs

    def from_db_value(  # pylint: disable=unused-argument
        self, value: typing.Optional[bytes], expression: typing.Any, condition: typing.Any
    ) -> typing.Optional[WrapperTypeVar]:
        """Called when data is loaded from the database.

        This is called when

        * An object is loaded from the database (``Certificate.objects.get()``, ...)
        * A queryset is used (*not* just creating it -> QS are lazy)
        """
        if value is None:
            return None
        return self.wrapper(value)

    def get_prep_value(
        self,
        value: typing.Optional[typing.Union[WrapperTypeVar, DecodableTypeVar]],
    ) -> typing.Optional[bytes]:
        """Get the raw database value.

        This is called when

        * ``Certificate.save()`` is called
        * Also called for queryset methods when using a field of this type (e.g. ``.filter(csr=...)``).
        """
        if not value:
            return None
        if isinstance(value, self.wrapper):
            return value.der
        return self.wrapper(value).der

    def formfield(self, **kwargs: typing.Any) -> forms.Field:
        defaults = {"form_class": self.formfield_class}
        defaults.update(kwargs)
        # TYPE NOTE: superclass seems to be not typed.
        return super().formfield(**defaults)  # type: ignore[no-any-return]

    def to_python(
        self,
        value: typing.Optional[typing.Union[WrapperTypeVar, DecodableTypeVar]],
    ) -> typing.Optional[WrapperTypeVar]:
        """Called during deserialization and during Certificate.full_clean().

        Note that this function is **not** called if the field value is ``None`` or ``b""``. It is however
        called with ``""`` (the empty string).
        """
        if not value:
            return None
        if isinstance(value, self.wrapper):
            return value
        return self.wrapper(value)


class CertificateSigningRequestField(
    LazyBinaryField[DecodableCertificateSigningRequest, LazyCertificateSigningRequest]
):
    """Django model field for CSRs."""

    formfield_class = CertificateSigningRequestFormField
    wrapper = LazyCertificateSigningRequest


class CertificateField(LazyBinaryField[DecodableCertificate, LazyCertificate]):
    """Django model field for Certificates."""

    # NOTE: Since certificates are never submitted in a form, there never is an active form field for this
    #       field, and formfield() is never called for this class. Thus it's okay to use the wrong class.
    formfield_class = CertificateSigningRequestFormField
    wrapper = LazyCertificate
