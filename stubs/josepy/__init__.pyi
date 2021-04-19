# pylint: skip-file
from collections.abc import Hashable
from typing import Any
from typing import Dict
from typing import FrozenSet
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

from .json_util import Field
from .json_util import JSONDeSerializable
from .json_util import JSONObjectWithFields
from .json_util import TypedJSONObjectWithFields
from .json_util import decode_b64jose
from .json_util import encode_b64jose

SignatureTypeVar = TypeVar("SignatureTypeVar", bound="Signature")


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
        alg: JWASignature,
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


RS256: JWASignature

__all__ = (
    "Field",
    "JSONDeSerializable",
    "JSONObjectWithFields",
    "TypedJSONObjectWithFields",
    "encode_b64jose",
    "decode_b64jose",
)
