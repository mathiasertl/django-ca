from django_ca.pydantic import (
    CRLDistributionPointsModel,
    DistributionPointModel,
    GeneralNameModel,
    NameAttributeModel,
    NameModel,
)

simple_distribution_point = DistributionPointModel(
    full_name=[GeneralNameModel(type="URI", value="https://ca.example.com/crl")]
)

# Unusual distribution point: not observed in practice, usually only a full name is used.
unusual_distribution_point = DistributionPointModel(
    relative_name=NameModel([NameAttributeModel(oid="2.5.4.3", value="example.com")]),
    crl_issuer=[GeneralNameModel(type="URI", value="https://ca.example.com/issuer")],
    reasons={"key_compromise"},
)

CRLDistributionPointsModel(value=[simple_distribution_point, unusual_distribution_point])
