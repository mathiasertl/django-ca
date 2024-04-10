from cryptography import x509
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID

# anyPolicy model with no qualifiers.
any_policy = x509.PolicyInformation(
    policy_identifier=CertificatePoliciesOID.ANY_POLICY,
    policy_qualifiers=None,
)

# CPS statement with a text and a user notice.
# NOTE: user notices are not observed in practice.
cps = x509.PolicyInformation(
    policy_identifier=CertificatePoliciesOID.CPS_QUALIFIER,
    policy_qualifiers=[
        "https://ca.example.com/cps",
        x509.UserNotice(explicit_text="my text", notice_reference=None),
    ],
)

x509.Extension(
    critical=False,
    oid=ExtensionOID.CERTIFICATE_POLICIES,
    value=x509.CertificatePolicies([any_policy, cps]),
)
