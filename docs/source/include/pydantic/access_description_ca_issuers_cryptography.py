from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

access_location = x509.UniformResourceIdentifier("http://ca-issuers.example.com")
x509.AccessDescription(
    access_method=AuthorityInformationAccessOID.CA_ISSUERS,
    access_location=access_location,
)
