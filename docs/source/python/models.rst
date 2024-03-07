#######################################
``django_ca.models`` - django-ca models
#######################################

**django-ca** uses three classes, called "models" in Django terminology, to store everything in the database.
They are the core classes for this project, if you want to use this project programmatically, you'll have to
use these classes:

* :ref:`CertificateAuthority <models-certificate-authority>` is used to store
  certificate authorities.
* :ref:`Certificate <models-certificate>` is used to store certificates.
* Finally, :ref:`Watcher <models-watcher>` stores email addresses for who should
  be notified if certificates expire.


Note that both ``CertificateAuthority`` and ``Certificate`` inherit from
:py:class:`~django_ca.models.X509CertMixin`, which provides many common
convenience methods.

.. _models-certificate-authority:

********************
CertificateAuthority
********************

.. autoclass:: django_ca.models.CertificateAuthority
   :members:
   :exclude-members: DoesNotExist, MultipleObjectsReturned

Creating CAs
============

Use ``CertificateAuthority.objects.init()`` to create new certificate authorities. The method has many options
but is designed to provide defaults that work in most cases::

   >>> from cryptography.x509.oid import NameOID
   >>> from django_ca.backends import key_backends
   >>> from django_ca.backends.storages import CreatePrivateKeyOptions, UsePrivateKeyOptions
   >>> from django_ca.models import CertificateAuthority
   >>> key_backend = key_backends["default"]
   >>> key_backend_options = CreatePrivateKeyOptions(password=None, path="ca", key_size=1024)
   >>> ca = CertificateAuthority.objects.init(
   ...     name='ca',
   ...     key_backend=key_backends["default"],
   ...     key_backend_options=key_backend_options,
   ...     parent_key_backend_options=UsePrivateKeyOptions(password=None),
   ...     subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]),
   ...     path_length=1  # so we can create one level of intermediate CAs
   ... )
   >>> ca
   <CertificateAuthority: ca>

This CA will contain all properties and X509 extensions to be a fully functioning CA. To create an
intermediate CA, simply pass the parent::

   >>> child = CertificateAuthority.objects.init(
   ...     name='child',
   ...     key_backend=key_backends["default"],
   ...     key_backend_options=key_backend_options,
   ...     parent_key_backend_options=UsePrivateKeyOptions(password=None),
   ...     subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child.example.com")]),
   ...     parent=ca
   ... )
   >>> child.parent
   <CertificateAuthority: ca>
   >>> ca.children.all()
   <CertificateAuthorityQuerySet [<CertificateAuthority: child>]>

Or to create a CA with all extensions that live CAs have, you can pass many more parameters::

   >>> from cryptography import x509
   >>> from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
   >>> full = CertificateAuthority.objects.init(
   ...     name='full',
   ...     key_backend=key_backends["default"],
   ...     key_backend_options=key_backend_options,
   ...     parent_key_backend_options=UsePrivateKeyOptions(password=None),
   ...     subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "full.example.com")]),
   ...     parent=ca,  # some extensions are only valid for intermediate CAs
   ...
   ...     # Extensions for the certificate authority itself
   ...     extensions=[
   ...         x509.Extension(
   ...             oid=ExtensionOID.NAME_CONSTRAINTS,
   ...             critical=True,
   ...             value=x509.NameConstraints(
   ...                 permitted_subtrees=[x509.DNSName('.com')],
   ...                 excluded_subtrees=None
   ...             ),
   ...         ),
   ...         x509.Extension(
   ...             oid=ExtensionOID.INHIBIT_ANY_POLICY,
   ...             critical=True,
   ...             value=x509.InhibitAnyPolicy(0)
   ...         )
   ...     ],
   ... )

You can also add extensions to be added to certificates when they are signed by this CA. These parameters can
always be added later (but of course, only new certificates will have the changed values).

.. NOTE::

   The Authority Information Access extension and the CRL Distribution Points extension are added
   automatically if you have the :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` setting configured.
   If you still give the parameters to ``init()``, the default values will be overwritten.

.. code-block:: python

   >>> from cryptography import x509
   >>> from cryptography.x509.oid import AuthorityInformationAccessOID, CertificatePoliciesOID, ExtensionOID
   >>> authority_information_access = x509.Extension(
   ...     oid=ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
   ...     critical=False,  # RFC 5280 says it should not be critical
   ...     value=x509.AuthorityInformationAccess(
   ...         [
   ...             x509.AccessDescription(
   ...                 access_method=AuthorityInformationAccessOID.OCSP,
   ...                 access_location=x509.UniformResourceIdentifier("http://ca.example.com/ocsp")
   ...             )
   ...         ]
   ...     )
   ... )
   >>> certificate_policies = x509.Extension(
   ...     oid=ExtensionOID.CERTIFICATE_POLICIES,
   ...     critical=False,  # RFC 5280 says it should not be critical
   ...     value=x509.CertificatePolicies(
   ...          [
   ...              x509.PolicyInformation(
   ...                  policy_identifier=CertificatePoliciesOID.CPS_USER_NOTICE,
   ...                  policy_qualifiers=["https://ca.example.com/cps"]
   ...              )
   ...          ]
   ...     )
   ... )
   >>> crl_distribution_points = x509.Extension(
   ...     oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
   ...     critical=False,
   ...     value=x509.CRLDistributionPoints(
   ...         [
   ...             x509.DistributionPoint(
   ...                 full_name=[x509.UniformResourceIdentifier("http://ca.example.com/crl")],
   ...                 relative_name=None,
   ...                 crl_issuer=None,
   ...                 reasons=None
   ...             )
   ...         ]
   ...     )
   ... )
   >>> issuer_alternative_name = x509.Extension(
   ...     oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
   ...     critical=False,
   ...     value=x509.IssuerAlternativeName(
   ...         [
   ...             x509.UniformResourceIdentifier("https://ca.example.com")
   ...         ]
   ...     )
   ... )
   >>> CertificateAuthority.objects.init(
   ...     name='add-extensions',
   ...     key_backend=key_backends["default"],
   ...     key_backend_options=key_backend_options,
   ...     parent_key_backend_options=UsePrivateKeyOptions(password=None),
   ...     subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "add-extensions")]),
   ...     sign_authority_information_access=authority_information_access,
   ...     sign_certificate_policies=certificate_policies,
   ...     sign_crl_distribution_points=crl_distribution_points,
   ...     sign_issuer_alternative_name=None,
   ... )
   <CertificateAuthority: add-extensions>


There are some more parameters to configure how the CA will be signed::

   >>> from cryptography.hazmat.primitives.asymmetric import ec
   >>> from cryptography.hazmat.primitives import hashes
   >>> key_backend_options = CreatePrivateKeyOptions(
   ...     password=b'foobar', path="ca", elliptic_curve=ec.SECP256R1()
   ... )
   >>> CertificateAuthority.objects.init(
   ...     name='props',
   ...     key_backend=key_backends["default"],
   ...     key_backend_options=key_backend_options,
   ...     parent_key_backend_options=UsePrivateKeyOptions(password=b'foobar'),
   ...     subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "child.example.com")]),
   ...     algorithm=hashes.SHA256(),  # SHA512 would be the default
   ...     path_length=3,  # three levels of intermediate CAs allowed,
   ...     key_type='EC',  # create a private key using Elliptic Curve cryptography
   ... )
   <CertificateAuthority: props>

Here are all parameters for creating CAs:

.. automethod:: django_ca.managers.CertificateAuthorityManager.init

.. _models-certificate:

***********
Certificate
***********

.. autoclass:: django_ca.models.Certificate
   :members:
   :exclude-members: DoesNotExist, MultipleObjectsReturned

Manager methods
===============

:py:class:`~django_ca.managers.CertificateManager` is the default manager for
:py:class:`~django_ca.models.Certificate`, meaning you can access it
using ``Certificate.objects``, e.g.::

   >>> csr  # doctest: +ELLIPSIS
   <...CertificateSigningRequest object at ...>
   >>> from django_ca.models import Certificate
   >>> Certificate.objects.create_cert(
   ...     ca=ca,
   ...     key_backend_options=UsePrivateKeyOptions(password=None),
   ...     csr=csr,
   ...     subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
   ... )
   <Certificate: example.com>

.. autoclass:: django_ca.managers.CertificateManager
   :members:

*************
X509CertMixin
*************

:py:class:`~django_ca.models.X509CertMixin` is a common base class to both
:py:class:`~django_ca.models.CertificateAuthority` and
:py:class:`~django_ca.models.Certificate` and provides many convenience
attributes.

.. autoclass:: django_ca.models.X509CertMixin
   :members:

.. _models-watcher:

********
Watchers
********

.. autoclass:: django_ca.models.Watcher
   :members:

****
ACME
****

.. autoclass:: django_ca.models.AcmeAccount
   :members:

.. autoclass:: django_ca.models.AcmeOrder
   :members:

.. autoclass:: django_ca.models.AcmeAuthorization
   :members:

.. autoclass:: django_ca.models.AcmeChallenge
   :members:

.. autoclass:: django_ca.models.AcmeCertificate
   :members:

