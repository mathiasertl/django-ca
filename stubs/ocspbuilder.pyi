import typing

from asn1crypto import keys
from asn1crypto import ocsp
from asn1crypto import x509
from oscrypto import asymmetric


class OCSPRequestBuilder:
    def __init__(
        self,
        certificate: typing.Union[x509.Certificate, asymmetric.Certificate],
        issuer: typing.Union[x509.Certificate, asymmetric.Certificate],
    ) -> None:
        ...

    def build(
        self,
        requestor_private_key: typing.Optional[
            typing.Union[keys.PrivateKeyInfo, asymmetric.PrivateKey]
        ] = None,
        requestor_certificate: typing.Optional[
            typing.Union[x509.Certificate, asymmetric.Certificate]
        ] = None,
        other_certificates: typing.Optional[
            typing.List[typing.Union[x509.Certificate, asymmetric.Certificate]]
        ] = None
    ) -> ocsp.OCSPRequest:
        ...

    @property
    def nonce(self) -> bool:
        ...

    @nonce.setter
    def nonce(self, value: bool) -> None:
        ...
