from django_ca.pydantic import GeneralNameModel, NameAttributeModel, NameModel

name = NameModel([NameAttributeModel(oid="CN", value="example.com")])
GeneralNameModel(type="dirName", value=name)
