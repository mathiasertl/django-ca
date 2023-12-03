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
