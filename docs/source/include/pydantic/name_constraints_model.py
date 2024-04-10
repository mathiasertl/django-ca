from django_ca.pydantic import (
    GeneralNameModel,
    NameConstraintsModel,
    NameConstraintsValueModel,
)

value = NameConstraintsValueModel(
    permitted_subtrees=[GeneralNameModel(type="DNS", value=".com")]
)
NameConstraintsModel(value=value)
