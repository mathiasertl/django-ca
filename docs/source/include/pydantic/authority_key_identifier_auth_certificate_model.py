from django_ca.pydantic import (
    AuthorityKeyIdentifierModel,
    AuthorityKeyIdentifierValueModel,
    GeneralNameModel,
)

AuthorityKeyIdentifierModel(
    value=AuthorityKeyIdentifierValueModel(
        key_identifier=None,
        authority_cert_issuer=[GeneralNameModel(type="URI", value="http://example.com")],
        authority_cert_serial_number=123,
    )
)
