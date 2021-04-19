# pylint: skip-file
import abc
from collections.abc import Hashable
from collections.abc import Mapping
from typing import Any
from typing import Callable
from typing import Dict
from typing import FrozenSet
from typing import Generic
from typing import Iterator
from typing import List
from typing import Optional
from typing import Type
from typing import TypeVar
from typing import Union

from OpenSSL import crypto
from cryptography.hazmat.backends.interfaces import Backend
from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

K = TypeVar('K')
V = TypeVar('V')
T = TypeVar('T')
JSONDeSerializableTypeVar = TypeVar('JSONDeSerializableTypeVar')
SignatureTypeVar = TypeVar("SignatureTypeVar", bound="Signature")


def decode_b64jose(data: str, size: Optional[int] = None, minimum: Optional[bool] = False) -> bytes:
    ...


def encode_b64jose(data: bytes) -> str:
    ...


class Error(Exception):
    ...


class DeserializationError(Error):
    ...


class ComparableKey:
    # NOTE: in reality, this comes from the wrapped public key
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo
    ) -> bytes:
        ...


class ImmutableMap(Mapping[K, V], Hashable):
    def __getitem__(self, key: K) -> V:
        ...

    def __hash__(self) -> int:
        ...

    def __iter__(self) -> Iterator[K]:
        ...

    def __len__(self) -> int:
        ...


class Field(Generic[T]):
    def __init__(
        self,
        json_name: str,
        default: Optional[T] = None,
        omitempty: Optional[bool] = False,
        decoder: Optional[Callable[[str], T]] = None,
        encoder: Optional[Callable[[T], str]] = None
    ) -> None:
        ...

    @classmethod
    def fdec(cls, value: str) -> T:
        ...


class JSONDeSerializable(abc.ABC):
    @classmethod
    def json_loads(
        cls: Type[JSONDeSerializableTypeVar],
        json_string: Union[str, bytes]
    ) -> JSONDeSerializableTypeVar:
        ...

    def to_json(self) -> Any:
        ...


class JSONObjectWithFields(JSONDeSerializable):
    _fields: Dict[str, Field[Any]]

    def __init__(self, **kwargs: Any) -> None:
        ...

    def encode(self, name: str) -> Any:
        ...


class TypedJSONObjectWithFields(ImmutableMap[str, Any], JSONObjectWithFields):
    ...


class JWK(TypedJSONObjectWithFields):
    key: ComparableKey

    @classmethod
    def load(
        cls: Type["JWK"],
        data: bytes,
        password: Optional[bytes] = None,
        backend: Optional[Backend] = None
    ) -> "JWK":
        ...

    def thumbprint(self, hash_function: Type[hashes.HashAlgorithm] = hashes.SHA256) -> bytes:
        ...


class JWA(JSONDeSerializable):
    ...


class JWASignature(JWA, Hashable):
    def __hash__(self) -> int:
        ...


class Header(JSONObjectWithFields):
    alg: JWASignature
    jwk: Optional[JWK]
    kid: Optional[str]
    nonce: bytes
    url: str


class Signature(JSONObjectWithFields):
    @classmethod
    def sign(
        cls: Type[SignatureTypeVar],
        payload: bytes,
        key: JWK,
        alg,
        include_jwk: bool = True,
        protect: FrozenSet[str] = frozenset(),
        **kwargs: Dict[str, Any]
    ) -> SignatureTypeVar:
        ...


class JWS(JSONObjectWithFields):
    payload: bytes
    signatures: List[Signature]

    @property
    def signature(self) -> Signature:
        ...

    def verify(self, key: Optional[JWK] = None) -> bool:
        ...


class ComparableX509:
    def __init__(self, wrapped: Union[crypto.X509, crypto.X509Req]) -> None:
        ...
