import josepy as jose


class Header(jose.Header):
    ...


class Signature(jose.Signature):
    combined: Header


class JWS(jose.JWS):
    @property
    def signature(self) -> Signature:
        ...
