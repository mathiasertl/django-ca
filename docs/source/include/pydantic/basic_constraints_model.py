from django_ca.pydantic import BasicConstraintsModel, BasicConstraintsValueModel

value = BasicConstraintsValueModel(ca=False, path_length=None)
BasicConstraintsModel(value=value)
