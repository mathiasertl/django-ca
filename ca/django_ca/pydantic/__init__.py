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
    AdmissionModel,
    AdmissionsValueModel,
    AuthorityKeyIdentifierValueModel,
    BasicConstraintsValueModel,
    DistributionPointModel,
    MSCertificateTemplateValueModel,
    NameConstraintsValueModel,
    NamingAuthorityModel,
    NoticeReferenceModel,
    PolicyConstraintsValueModel,
    PolicyInformationModel,
    ProfessionInfoModel,
    UnrecognizedExtensionValueModel,
    UserNoticeModel,
)
from django_ca.pydantic.extensions import (
    AdmissionsModel,
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
    "AdmissionModel",
    "AdmissionsModel",
    "AdmissionsValueModel",
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
    "NamingAuthorityModel",
    "NoticeReferenceModel",
    "OCSPNoCheckModel",
    "OtherNameModel",
    "PolicyConstraintsModel",
    "PolicyConstraintsValueModel",
    "PolicyInformationModel",
    "PrecertPoisonModel",
    "PrecertificateSignedCertificateTimestampsModel",
    "ProfessionInfoModel",
    "SignedCertificateTimestampsModel",
    "SubjectAlternativeNameModel",
    "SubjectInformationAccessModel",
    "SubjectKeyIdentifierModel",
    "TLSFeatureModel",
    "UnrecognizedExtensionModel",
    "UnrecognizedExtensionValueModel",
    "UserNoticeModel",
)
