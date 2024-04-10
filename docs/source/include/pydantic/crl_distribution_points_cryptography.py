from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

simple_distribution_point = x509.DistributionPoint(
    full_name=[x509.UniformResourceIdentifier("https://ca.example.com/crl")],
    relative_name=None,
    crl_issuer=None,
    reasons=None,
)

# Unusual distribution point: not observed in practice, usually only a full name is used.
unusual_distribution_point = x509.DistributionPoint(
    full_name=None,
    relative_name=x509.RelativeDistinguishedName(
        [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")]
    ),
    crl_issuer=[x509.UniformResourceIdentifier("https://ca.example.com/issuer")],
    reasons=frozenset([x509.ReasonFlags.key_compromise]),
)

x509.Extension(
    critical=False,
    oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
    value=x509.CRLDistributionPoints(
        [simple_distribution_point, unusual_distribution_point]
    ),
)
