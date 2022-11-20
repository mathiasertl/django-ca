##########################################
``django_ca.extensions`` - X509 extensions
##########################################

.. foo::

   this should still be done

The extension classes provided by **django-ca** act as convenience classes for handling extensions. They
abstract away the complex API of cryptography and have some advanced data handling functions. As a
constructor, they always take either a ``dict`` or a cryptography extension::

   >>> from django_ca.extensions import KeyUsage
   >>> KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
   <KeyUsage: ['key_agreement', 'key_encipherment'], critical=True>

... but you can also pass an equivalent cryptography extension::

   >>> from cryptography import x509
   >>> from cryptography.x509.oid import ExtensionOID
   >>> KeyUsage(x509.Extension(
   ...     oid=ExtensionOID.KEY_USAGE, critical=True, value=x509.KeyUsage(
   ...         key_agreement=True, key_encipherment=True, digital_signature=False, crl_sign=False,
   ...         content_commitment=False, data_encipherment=False, key_cert_sign=False, encipher_only=False,
   ...         decipher_only=False)
   ... ))
   <KeyUsage: ['key_agreement', 'key_encipherment'], critical=True>

... regardless of how you created the extension, you can modify it at will until you actually use it
somewhere::

   >>> from django_ca.extensions import KeyUsage
   >>> ku = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
   >>> ku |= ['nonRepudiation']
   >>> ku.add('cRLSign')
   >>> ku
   <KeyUsage: ['content_commitment', 'crl_sign', 'key_agreement', 'key_encipherment'], critical=True>

You can always convert extensions to valid cryptography extensions::

   >>> ku.extension_type  # doctest: +ELLIPSIS
   <KeyUsage(digital_signature=False, ...)>
   >>> ku.as_extension()  # doctest: +ELLIPSIS
   <Extension(oid=<ObjectIdentifier(oid=2.5.29.15, name=keyUsage)>, critical=True, value=<KeyUsage(...)>)>

Many extensions are modeled after builtin python types and are designed to be handled in a similar way.
For example, :py:class:`~django_ca.extensions.KeyUsage` inherits from
:py:mod:`~django_ca.extensions.base.OrderedSetExtension`, and thus handles like an ordered set::

    >>> ku = KeyUsage()
    >>> ku |= {'decipherOnly', }
    >>> ku |= KeyUsage({'value': ['digitalSignature']})
    >>> ku
    <KeyUsage: ['decipher_only', 'digital_signature'], critical=True>
    >>> ku.add('nonRepudiation')
    >>> ku.add('nonRepudiation')
    >>> ku
    <KeyUsage: ['content_commitment', 'decipher_only', 'digital_signature'], critical=True>

When passing a dictionary, you can always pass a ``critical`` value.  If omitted, the default value is
determined by the ``default_critical`` flag, which matches common X.509 usage for each extension::

    >>> KeyUsage()
    <KeyUsage: [], critical=True>
    >>> KeyUsage({'critical': False})
    <KeyUsage: [], critical=False>

You can always serialize an extension to its ``dict`` representation and later restore it (e.g. after sending
it over the network)::

   >>> ku = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
   >>> ku == KeyUsage(ku.serialize())
   True

.. _extensions:

*****************
Extension classes
*****************

.. automodule:: django_ca.extensions
   :show-inheritance:
   :members:
   :exclude-members: get_extension_name

************************
Helper functions/classes
************************

In addition to extension classes, there are a few helper functions to ease handling of extensions:

.. autofunction:: django_ca.extensions.get_extension_name

.. autoattribute:: django_ca.extensions.KEY_TO_EXTENSION
   :annotation: {'basic_constraints': <class 'django_ca.extensions.BasicConstraints'>, ...}

   A dictionary mapping of a unique key to an extension class::

      >>> KEY_TO_EXTENSION['authority_information_access'].__name__
      'AuthorityInformationAccess'

.. autoattribute:: django_ca.extensions.OID_TO_EXTENSION
   :annotation: {<ObjectIdentifier(oid=...): <class 'django_ca.extensions...>, ...}

   A dictionary mapping of OIDs to extension classes::

      >>> from cryptography.x509.oid import ExtensionOID
      >>> OID_TO_EXTENSION[ExtensionOID.BASIC_CONSTRAINTS].__name__
      'BasicConstraints'

``django_ca.extensions.utils``
==============================

.. automodule:: django_ca.extensions.utils
   :show-inheritance:
   :members:
