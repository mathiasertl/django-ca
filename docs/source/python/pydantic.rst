########################################
``django_ca.pydantic`` - Pydantic models
########################################

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

.. autoclass:: django_ca.pydantic.name.NameAttributeModel
   :members:

.. autoclass:: django_ca.pydantic.name.NameModel
   :members:

GeneralName
===========

.. autoclass:: django_ca.pydantic.general_name.GeneralNameModel
   :members:

.. autoclass:: django_ca.pydantic.general_name.OtherNameModel
   :members:

Extensions
==========

.. automodule:: django_ca.pydantic.extensions
   :members:
   :exclude-members: CRLNumberModel, DeltaCRLIndicatorModel, ExtensionModel, BaseExtensionModel,
        NoValueExtensionModel, AlternativeNameBaseModel, CRLExtensionBaseModel, InformationAccessBaseModel,
        SignedCertificateTimestampBaseModel

.. _pydantic_extension_attributes:

Extension attributes
====================

.. automodule:: django_ca.pydantic.extension_attributes
   :members:

CRL extensions
==============

Models for CRL extensions are not currently used within the project itself.

.. autoclass:: django_ca.pydantic.extensions.CRLNumberModel

.. autoclass:: django_ca.pydantic.extensions.DeltaCRLIndicatorModel
