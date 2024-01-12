from cryptography.x509.oid import NameOID

CA_DEFAULT_NAME_ORDER = (
    "countryName",
    NameOID.ORGANIZATION_NAME,
    "2.5.4.3",  # OID for commonName
)
