from cryptography import x509
from cryptography.x509.oid import NameOID

CA_DEFAULT_SUBJECT = (
    {"oid": "countryName", "value": "AT"},
    {"oid": "2.5.4.8", "value": "Vienna"},  # dottet string for "stateOrProvinceName"
    {"oid": NameOID.ORGANIZATION_NAME, "value": "orgName"},
    x509.NameAttribute(oid=NameOID.ORGANIZATIONAL_UNIT_NAME, value="orgUnitName"),
)

# Or you just define the full name:
# CA_DEFAULT_SUBJECT = x509.Name(...)
