from django_ca.pydantic import AccessDescriptionModel, GeneralNameModel

access_location = GeneralNameModel(type="URI", value="http://ca-issuers.example.com")
AccessDescriptionModel(
    access_method="ca_issuers",  # or the OID: "1.3.6.1.5.5.7.48.2"
    access_location=access_location,
)
