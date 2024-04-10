from django_ca.pydantic import (
    GeneralNameModel,
    NameConstraintsModel,
    NameConstraintsValueModel,
)

value = NameConstraintsValueModel(
    permitted_subtrees=[GeneralNameModel(type="DNS", value=".com")],
    excluded_subtrees=[
        GeneralNameModel(type="DNS", value="one.example.com"),
        GeneralNameModel(type="DNS", value="two.example.com"),
    ],
)
NameConstraintsModel(value=value)
