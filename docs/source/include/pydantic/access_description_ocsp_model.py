from django_ca.pydantic import AccessDescriptionModel, GeneralNameModel

access_location = GeneralNameModel(type="URI", value="http://ocsp.example.com")
AccessDescriptionModel(
    access_method="ocsp",  # or the OID: "1.3.6.1.5.5.7.48.1"
    access_location=access_location,
)
