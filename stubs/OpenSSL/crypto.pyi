import typing
from datetime import datetime

from cryptography import x509

FILETYPE_PEM: int
FILETYPE_ASN1: int
FILETYPE_TEXT: int


class X509:
    ...


class X509Req:
    @classmethod
    def from_cryptography(cls, crypto_req: x509.CertificateSigningRequest) -> "X509Req":
        ...


def load_certificate(type: int, buffer: bytes) -> X509:
    ...


class X509Store:
    def __init__(self) -> None:
        ...

    def add_cert(self, cert: X509) -> None:
        ...

    def set_time(self, vfy_time: datetime) -> None:
        ...


class X509StoreContext:
    def __init__(
        self, store: X509Store, certificate: X509, chain: typing.Optional[typing.List[X509]] = None
    ) -> None:
        ...

    def verify_certificate(self) -> None:
        ...
