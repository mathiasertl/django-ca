from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(
    critical=True,
    oid=ExtensionOID.KEY_USAGE,
    value=x509.KeyUsage(
        content_commitment=False,
        crl_sign=False,
        data_encipherment=False,
        decipher_only=False,
        digital_signature=False,
        encipher_only=False,
        key_agreement=True,
        key_cert_sign=False,
        key_encipherment=True,
    ),
)
