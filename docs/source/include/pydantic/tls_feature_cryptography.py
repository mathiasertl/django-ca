from cryptography import x509
from cryptography.x509.oid import ExtensionOID

x509.Extension(
    critical=False,
    oid=ExtensionOID.TLS_FEATURE,
    value=x509.TLSFeature([x509.TLSFeatureType.status_request]),
)
