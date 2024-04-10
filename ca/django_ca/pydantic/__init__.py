# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Pydantic modules included in django-ca."""

from django_ca.pydantic.extension_attributes import (
    AccessDescriptionModel,
    AuthorityKeyIdentifierValueModel,
    BasicConstraintsValueModel,
    DistributionPointModel,
    MSCertificateTemplateValueModel,
    NameConstraintsValueModel,
    NoticeReferenceModel,
    PolicyConstraintsValueModel,
    PolicyInformationModel,
    UnrecognizedExtensionValueModel,
    UserNoticeModel,
)
from django_ca.pydantic.extensions import (
    AuthorityInformationAccessModel,
    AuthorityKeyIdentifierModel,
    BasicConstraintsModel,
    CertificatePoliciesModel,
    CRLDistributionPointsModel,
    CRLNumberModel,
    DeltaCRLIndicatorModel,
    ExtendedKeyUsageModel,
    FreshestCRLModel,
    InhibitAnyPolicyModel,
    IssuerAlternativeNameModel,
    KeyUsageModel,
    MSCertificateTemplateModel,
    NameConstraintsModel,
    OCSPNoCheckModel,
    PolicyConstraintsModel,
    PrecertificateSignedCertificateTimestampsModel,
    PrecertPoisonModel,
    SignedCertificateTimestampsModel,
    SubjectAlternativeNameModel,
    SubjectInformationAccessModel,
    SubjectKeyIdentifierModel,
    TLSFeatureModel,
    UnrecognizedExtensionModel,
)
from django_ca.pydantic.general_name import GeneralNameModel, OtherNameModel
from django_ca.pydantic.name import NameAttributeModel, NameModel

__all__ = (
    "AccessDescriptionModel",
    "AuthorityInformationAccessModel",
    "AuthorityKeyIdentifierModel",
    "AuthorityKeyIdentifierValueModel",
    "BasicConstraintsModel",
    "BasicConstraintsValueModel",
    "CRLDistributionPointsModel",
    "CRLNumberModel",
    "CertificatePoliciesModel",
    "DeltaCRLIndicatorModel",
    "DistributionPointModel",
    "ExtendedKeyUsageModel",
    "FreshestCRLModel",
    "GeneralNameModel",
    "InhibitAnyPolicyModel",
    "IssuerAlternativeNameModel",
    "KeyUsageModel",
    "MSCertificateTemplateModel",
    "MSCertificateTemplateValueModel",
    "NameAttributeModel",
    "NameConstraintsModel",
    "NameConstraintsValueModel",
    "NameModel",
    "NoticeReferenceModel",
    "OCSPNoCheckModel",
    "OtherNameModel",
    "PolicyConstraintsModel",
    "PolicyConstraintsValueModel",
    "PolicyInformationModel",
    "PrecertPoisonModel",
    "PrecertificateSignedCertificateTimestampsModel",
    "SignedCertificateTimestampsModel",
    "SubjectAlternativeNameModel",
    "SubjectInformationAccessModel",
    "SubjectKeyIdentifierModel",
    "TLSFeatureModel",
    "UnrecognizedExtensionModel",
    "UnrecognizedExtensionValueModel",
    "UserNoticeModel",
)
