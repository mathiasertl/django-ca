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

from .b64 import b64decode
from .b64 import b64encode
from .json_util import Field
from .json_util import JSONDeSerializable
from .json_util import JSONObjectWithFields
from .json_util import TypedJSONObjectWithFields
from .json_util import decode_b64jose
from .json_util import encode_b64jose
from .jwk import JWK
from .jwk import JWKRSA
from .util import ComparableKey
from .util import ComparableRSAKey

SignatureTypeVar = TypeVar("SignatureTypeVar", bound="Signature")


class Error(Exception):
    ...


class DeserializationError(Error):
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
    "ComparableKey",
    "ComparableRSAKey",
    "Field",
    "JSONDeSerializable",
    "JSONObjectWithFields",
    "JWK",
    "JWKRSA",
    "TypedJSONObjectWithFields",
    "b64decode",
    "b64encode",
    "encode_b64jose",
    "decode_b64jose",
)
