##########################################
``django_ca.extensions`` - X509 extensions
##########################################

The extension classes provided by **django-ca** act as convenience classes for handling extensions. They
abstract away the complex API of cryptography and have some advanced data handling functions. As a
constructor, they always take either a ``dict`` or a cryptography extension::

   >>> from django_ca.extensions import KeyUsage
   >>> KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
   <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=True>

... but you can also pass an equivalent cryptography extension::

   >>> from cryptography import x509
   >>> from cryptography.x509.oid import ExtensionOID
   >>> KeyUsage(x509.Extension(
   ...     oid=ExtensionOID.KEY_USAGE, critical=True, value=x509.KeyUsage(
   ...         key_agreement=True, key_encipherment=True, digital_signature=False, crl_sign=False,
   ...         content_commitment=False, data_encipherment=False, key_cert_sign=False, encipher_only=False,
   ...         decipher_only=False)
   ... ))
   <KeyUsage: ['keyAgreement', 'keyEncipherment'], critical=True>

... regardless of how you created the extension, you can modify it at will until you actually use it
somewhere::

   >>> from django_ca.extensions import KeyUsage
   >>> ku = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
   >>> ku |= ['nonRepudiation']
   >>> ku.add('cRLSign')
   >>> ku
   <KeyUsage: ['cRLSign', 'keyAgreement', 'keyEncipherment', 'nonRepudiation'], critical=True>

The type of operations available to an extension depend on the extension.

You can always serialize an extension to its ``dict`` representation and later restore it (e.g. after
transfering it over the network)::

   >>> ku = KeyUsage({'value': ['keyAgreement', 'keyEncipherment']})
   >>> ku == KeyUsage(ku.serialize())
   True

.. _extensions:

*****************
Extension classes
*****************

Note that extensions are not marked as "critical" by default. Only those that are usually marked as critical
override the ``default_critical`` attribute.

.. automodule:: django_ca.extensions
   :show-inheritance:
   :members:
   :exclude-members: Extension, IterableExtension, ListExtension, OrderedSetExtension, AlternativeNameExtension, KeyIdExtension, NullExtension, DistributionPoint, PolicyInformation, CRLDistributionPointsBase

*****************
Attribute classes
*****************

.. autoclass:: django_ca.extensions.DistributionPoint
   :members:

.. autoclass:: django_ca.extensions.PolicyInformation
   :members:

************
Base classes
************

.. autoclass:: django_ca.extensions.Extension
   :members:

.. autoclass:: django_ca.extensions.IterableExtension
   :show-inheritance:
   :members:

.. autoclass:: django_ca.extensions.ListExtension
   :show-inheritance:
   :members:

.. autoclass:: django_ca.extensions.OrderedSetExtension
   :show-inheritance:
   :members:

.. autoclass:: django_ca.extensions.KeyIdExtension
   :show-inheritance:
   :members:

.. autoclass:: django_ca.extensions.CRLDistributionPointsBase
   :show-inheritance:
   :members:

.. autoclass:: django_ca.extensions.AlternativeNameExtension
   :show-inheritance:
   :members:

.. autoclass:: django_ca.extensions.NullExtension
   :show-inheritance:
   :members:
