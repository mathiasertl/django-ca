from django_ca.pydantic import BasicConstraintsModel, BasicConstraintsValueModel

value = BasicConstraintsValueModel(ca=True, path_length=0)
BasicConstraintsModel(value=value)
