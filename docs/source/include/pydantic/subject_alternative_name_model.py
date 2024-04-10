from django_ca.pydantic import GeneralNameModel, SubjectAlternativeNameModel

SubjectAlternativeNameModel(
    value=[
        GeneralNameModel(type="DNS", value="example.com"),
        GeneralNameModel(type="DNS", value="example.net"),
    ]
)
