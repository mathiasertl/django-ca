import typing
import josepy as jose


class Header(jose.Header):
    ...


class Signature(jose.Signature):
    combined: Header


class JWS(jose.JWS):
    @classmethod
    def sign(
        cls,
        payload: bytes,
        key: jose.JWK,
        alg: jose.JWASignature,
        nonce: bytes,
        url: typing.Optional[str] = None,
        kid: typing.Optional[str] = None,
    ) -> jose.JWS:
        ...

    @property
    def signature(self) -> Signature:
        ...
