import typing
import josepy as jose


class Header(jose.jws.Header):
    nonce: typing.Optional[bytes]
    url: typing.Optional[str]


class Signature(jose.jws.Signature):
    combined: Header


class JWS(jose.jws.JWS):
    # TYPE NOTE: ACME.jws REALLY overrides with a different signature
    @classmethod
    def sign(  # type: ignore[override]
        cls,
        payload: bytes,
        key: jose.jwk.JWK,
        alg: jose.jwa.JWASignature,
        nonce: bytes,
        url: typing.Optional[str] = None,
        kid: typing.Optional[str] = None,
    ) -> jose.jws.JWS:
        ...

    @property
    def signature(self) -> Signature:
        ...
