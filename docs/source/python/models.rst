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

   >>> from django_ca.models import CertificateAuthority
   >>> from django_ca.utils import x509_name
   >>> ca = CertificateAuthority.objects.init(
   ...   name='ca',
   ...   subject=x509_name('/CN=ca.example.com'),
   ...   path_length=1  # so we can create one level of intermediate CAs
   ... )
   >>> ca
   <CertificateAuthority: ca>

This CA will contain all properties and X509 extensions to be a fully functioning CA. To create an
intermediate CA, simply pass the parent::

   >>> child = CertificateAuthority.objects.init(
   ...   name='child',
   ...   subject=x509_name('/CN=child.example.com'),
   ...   parent=ca)
   >>> child.parent
   <CertificateAuthority: ca>
   >>> ca.children.all()
   <CertificateAuthorityQuerySet [<CertificateAuthority: child>]>

Or to create a CA with all extensions that live CAs have, you can pass many more parameters::

   >>> from cryptography import x509
   >>> from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
   >>> full = CertificateAuthority.objects.init(
   ...   name='full',
   ...   subject=x509_name('/CN=full.example.com'),
   ...   parent=ca,  # some extensions are only valid for intermediate CAs
   ...   issuer_url='http://full.example.com/full.der',
   ...
   ...   # Extensions for the certificate authority itself
   ...   extensions=[
   ...       x509.Extension(
   ...           oid=ExtensionOID.NAME_CONSTRAINTS,
   ...           critical=True,
   ...           value=x509.NameConstraints(
   ...               permitted_subtrees=[x509.DNSName('.com')],
   ...               excluded_subtrees=None
   ...           ),
   ...       ),
   ...       x509.Extension(
   ...           oid=ExtensionOID.INHIBIT_ANY_POLICY,
   ...           critical=True,
   ...           value=x509.InhibitAnyPolicy(0)
   ...       )
   ...   ],
   ...
   ...   # CRL/OCSP URLs for signed certificates. These can be changed later:
   ...   crl_url=['http://full.example.com/full.crl'],
   ...   ocsp_url='http://full.example.com/ocsp',
   ... )

There are some more parameters to configure how the CA will be signed::

   >>> from cryptography.hazmat.primitives.asymmetric import ec
   >>> from cryptography.hazmat.primitives import hashes
   >>> CertificateAuthority.objects.init(
   ...   name='props',
   ...   subject=x509_name('/CN=child.example.com'),
   ...   algorithm=hashes.SHA256(),  # SHA512 would be the default
   ...   path_length=3,  # three levels of intermediate CAs allowed,
   ...   password=b'foobar',  # encrypt private key with this password
   ...   key_type='EC',  # create a private key using Elliptic Curve cryptography
   ...   elliptic_curve=ec.SECP256R1()  # Elliptic curve for the key
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
   >>> Certificate.objects.create_cert(csr=csr, ca=ca, subject=x509_name('/CN=example.com'))
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

