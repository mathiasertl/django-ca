from cryptography import x509
from cryptography.x509.oid import ExtensionOID

value = x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=1)
x509.Extension(critical=True, oid=ExtensionOID.POLICY_CONSTRAINTS, value=value)
