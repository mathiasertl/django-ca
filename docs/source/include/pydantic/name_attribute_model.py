from django_ca.pydantic import NameAttributeModel

NameAttributeModel(
    oid="CN",  #  or "commonName" or NameOID.COMMON_NAME or just "2.5.4.3"
    value="example.com",
)
