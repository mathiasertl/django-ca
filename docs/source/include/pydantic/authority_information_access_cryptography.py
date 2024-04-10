from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

x509.Extension(
    critical=False,
    oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
    value=x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.OCSP,
                access_location=x509.UniformResourceIdentifier("http://ocsp.example.com"),
            ),
            x509.AccessDescription(
                access_method=AuthorityInformationAccessOID.CA_ISSUERS,
                access_location=x509.UniformResourceIdentifier("http://example.com"),
            ),
        ]
    ),
)
