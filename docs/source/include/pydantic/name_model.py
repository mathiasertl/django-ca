from django_ca.pydantic import NameAttributeModel, NameModel

NameModel(
    [
        NameAttributeModel(oid="C", value="AT"),
        NameAttributeModel(oid="CN", value="example.com"),
    ]
)
