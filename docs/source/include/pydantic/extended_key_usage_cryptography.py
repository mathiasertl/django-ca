from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

x509.Extension(
    critical=False,
    oid=ExtensionOID.EXTENDED_KEY_USAGE,
    value=x509.ExtendedKeyUsage(
        [ExtendedKeyUsageOID.CLIENT_AUTH, x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]
    ),
)
