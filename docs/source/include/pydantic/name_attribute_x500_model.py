import base64

from django_ca.pydantic import NameAttributeModel

value = base64.b64encode(b"example.com")
NameAttributeModel(oid="x500UniqueIdentifier", value=value)
