from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

access_location = x509.UniformResourceIdentifier("http://ocsp.example.com")
x509.AccessDescription(
    access_method=AuthorityInformationAccessOID.OCSP, access_location=access_location
)
