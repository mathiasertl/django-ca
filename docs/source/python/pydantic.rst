########################################
``django_ca.pydantic`` - Pydantic models
########################################

************
Type aliases
************

.. automodule:: django_ca.pydantic.type_aliases
   :members:

********************
Cryptography classes
********************

All cryptography-related classes share that they can be instantiated from cryptography instances using
:py:func:`~pydantic.main.BaseModel.model_validate` and share a ``cryptography`` property that converts a model
instance into a cryptography instance:

    >>> from cryptography import x509
    >>> from cryptography.x509.oid import NameOID
    >>> from django_ca.pydantic.name import NameAttributeModel
    >>> attr = x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")
    >>> model = NameAttributeModel.model_validate(attr)
    >>> model
    NameAttributeModel(oid='2.5.4.3', value='example.com')
    >>> model.cryptography == attr
    True

Name
====

.. autoclass:: django_ca.pydantic.NameAttributeModel
   :members:
   :exclude-members: parse_cryptography, validate_name_attribute

.. autoclass:: django_ca.pydantic.NameModel
   :members:
   :exclude-members: parse_cryptography, validate_duplicates

GeneralName
===========

.. autoclass:: django_ca.pydantic.GeneralNameModel
   :members:
   :exclude-members: parse_cryptography, validate_value

.. autoclass:: django_ca.pydantic.OtherNameModel
   :members:
   :exclude-members: parse_cryptography, check_consistency

Extensions
==========

.. automodule:: django_ca.pydantic.extensions

.. autoclass:: django_ca.pydantic.AuthorityInformationAccessModel

.. autoclass:: django_ca.pydantic.AuthorityKeyIdentifierModel

.. autoclass:: django_ca.pydantic.BasicConstraintsModel

.. autoclass:: django_ca.pydantic.CRLDistributionPointsModel

.. autoclass:: django_ca.pydantic.CertificatePoliciesModel

.. autoclass:: django_ca.pydantic.ExtendedKeyUsageModel

.. autoclass:: django_ca.pydantic.FreshestCRLModel

.. autoclass:: django_ca.pydantic.InhibitAnyPolicyModel

.. autoclass:: django_ca.pydantic.IssuerAlternativeNameModel

.. autoclass:: django_ca.pydantic.KeyUsageModel

.. autoclass:: django_ca.pydantic.MSCertificateTemplateModel

.. autoclass:: django_ca.pydantic.NameConstraintsModel

.. autoclass:: django_ca.pydantic.OCSPNoCheckModel

.. autoclass:: django_ca.pydantic.PolicyConstraintsModel

.. autoclass:: django_ca.pydantic.PrecertPoisonModel

.. autoclass:: django_ca.pydantic.PrecertificateSignedCertificateTimestampsModel

.. autoclass:: django_ca.pydantic.SignedCertificateTimestampsModel

.. autoclass:: django_ca.pydantic.SubjectAlternativeNameModel

.. autoclass:: django_ca.pydantic.SubjectInformationAccessModel

.. autoclass:: django_ca.pydantic.SubjectKeyIdentifierModel

.. autoclass:: django_ca.pydantic.TLSFeatureModel

.. autoclass:: django_ca.pydantic.UnrecognizedExtensionModel

.. _pydantic_extension_attributes:

Extension attributes
====================

.. automodule:: django_ca.pydantic.extension_attributes
   :members:
   :exclude-members: parse_cryptography

CRL extensions
==============

Models for CRL extensions are not currently used within the project itself.

.. autoclass:: django_ca.pydantic.CRLNumberModel

.. autoclass:: django_ca.pydantic.DeltaCRLIndicatorModel
