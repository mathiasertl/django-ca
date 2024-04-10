from django_ca.pydantic import (
    AuthorityKeyIdentifierModel,
    AuthorityKeyIdentifierValueModel,
)

AuthorityKeyIdentifierModel(
    value=AuthorityKeyIdentifierValueModel(key_identifier=b"MTIz")
)
