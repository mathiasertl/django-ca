import typing

from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

K = typing.TypeVar('K')
V = typing.TypeVar('V')
PrivKey = typing.TypeVar('PrivKey', rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey)
PubKey = typing.TypeVar('PubKey')


class ComparableKey(typing.Generic[PrivKey, PubKey]):
    def __init__(self, wrapped: typing.Union[PrivKey, PubKey]) -> None:
        ...

    # NOTE: in reality, this comes from the wrapped public key
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo
    ) -> bytes:
        ...


class ComparableRSAKey(ComparableKey[rsa.RSAPrivateKeyWithSerialization, rsa.RSAPublicKeyWithSerialization]):
    ...


class ImmutableMap(typing.Mapping[K, V], typing.Hashable):
    def __getitem__(self, key: K) -> V:
        ...

    def __hash__(self) -> int:
        ...

    def __iter__(self) -> typing.Iterator[K]:
        ...

    def __len__(self) -> int:
        ...
