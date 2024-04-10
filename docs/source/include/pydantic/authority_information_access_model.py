from django_ca.pydantic import (
    AccessDescriptionModel,
    AuthorityInformationAccessModel,
    GeneralNameModel,
)

AuthorityInformationAccessModel(
    value=[
        AccessDescriptionModel(
            access_method="ocsp",
            access_location=GeneralNameModel(type="URI", value="http://ocsp.example.com"),
        ),
        AccessDescriptionModel(
            access_method="ca_issuers",
            access_location=GeneralNameModel(type="URI", value="http://example.com"),
        ),
    ]
)
