import abc
import typing

import OpenSSL.crypto

from .util import ImmutableMap

T = typing.TypeVar('T')
JSONDeSerializableTypeVar = typing.TypeVar('JSONDeSerializableTypeVar')


class Field(typing.Generic[T]):
    def __init__(
        self,
        json_name: str,
        default: typing.Optional[T] = None,
        omitempty: typing.Optional[bool] = False,
        decoder: typing.Optional[typing.Callable[[str], T]] = None,
        encoder: typing.Optional[typing.Callable[[T], str]] = None
    ) -> None:
        ...

    @classmethod
    def fdec(cls, value: str) -> T:
        ...


class JSONDeSerializable(abc.ABC):
    @classmethod
    def json_loads(
        cls: typing.Type[JSONDeSerializableTypeVar],
        json_string: typing.Union[str, bytes]
    ) -> JSONDeSerializableTypeVar:
        ...

    def to_json(self) -> typing.Any:
        ...


class JSONObjectWithFields(JSONDeSerializable):
    _fields: typing.Dict[str, Field[typing.Any]]

    def __init__(self, **kwargs: typing.Any) -> None:
        ...

    def encode(self, name: str) -> typing.Any:
        ...


class TypedJSONObjectWithFields(ImmutableMap[str, typing.Any], JSONObjectWithFields):
    ...


def decode_b64jose(
    data: str, size: typing.Optional[int] = None, minimum: typing.Optional[bool] = False
) -> bytes:
    ...


def encode_b64jose(data: bytes) -> str:
    ...


def decode_csr(csr: str) -> OpenSSL.crypto.X509Req:
    ...


def encode_csr(csr: OpenSSL.crypto.X509Req) -> str:
    ...
