import typing

from cryptography.hazmat.backends.interfaces import Backend
from cryptography.hazmat.primitives import hashes

from .json_util import TypedJSONObjectWithFields
from .util import ComparableKey


class JWK(TypedJSONObjectWithFields):
    key: ComparableKey[typing.Any, typing.Any]

    @classmethod
    def load(
        cls: typing.Type["JWK"],
        data: bytes,
        password: typing.Optional[bytes] = None,
        backend: typing.Optional[Backend] = None
    ) -> "JWK":
        ...

    def thumbprint(self, hash_function: typing.Type[hashes.HashAlgorithm] = hashes.SHA256) -> bytes:
        ...


class JWKRSA(JWK):
    ...
