import typing

from asn1crypto.keys import PrivateKeyInfo


class PrivateKey:
    @property
    def algorithm(self) -> typing.Literal["rsa", "dsa", "ec"]:  # according to docs
        ...


class Certificate:
    ...


def load_private_key(
    source: typing.Union[bytes, str, PrivateKeyInfo],
    password: typing.Optional[typing.Union[bytes, str]] = None,
) -> PrivateKey:
    ...


def dsa_sign(private_key: PrivateKey, data: bytes, hash_algorithm: str) -> bytes:
    ...


def ecdsa_sign(private_key: PrivateKey, data: bytes, hash_algorithm: str) -> bytes:
    ...


def rsa_pkcs1v15_sign(private_key: PrivateKey, data: bytes, hash_algorithm: str) -> bytes:
    ...
