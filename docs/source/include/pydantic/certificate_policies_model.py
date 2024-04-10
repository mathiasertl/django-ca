from django_ca.pydantic import (
    CertificatePoliciesModel,
    PolicyInformationModel,
    UserNoticeModel,
)

# anyPolicy model with no qualifiers.
any_policy = PolicyInformationModel(policy_identifier="2.5.29.32.0")

# CPS statement with a text and a user notice.
# NOTE: user notices are not observed in practice.
cps = PolicyInformationModel(
    policy_identifier="1.3.6.1.5.5.7.2.1",
    policy_qualifiers=[
        "https://ca.example.com/cps",
        UserNoticeModel(explicit_text="my text"),
    ],
)

CertificatePoliciesModel(value=[any_policy, cps])
