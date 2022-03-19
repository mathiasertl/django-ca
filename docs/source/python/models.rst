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

Use ``CertificateAuthority.objects.init()`` to create new certificate
authorities. The method has many options but is designed to provide defaults
that work in most cases::

   >>> from django_ca.models import CertificateAuthority
   >>> from django_ca.utils import x509_name
   >>> ca = CertificateAuthority.objects.init(
   ...   name='ca', 
   ...   subject=x509_name('/CN=ca.example.com'),
   ...   pathlen=1  # so we can create one level of intermediate CAs
   ... )
   >>> ca
   <CertificateAuthority: ca>

This CA will contain all properties and X509 extensions to be a fully
functioning CA. To create an intermediate CA, simply pass the parent::

   >>> child = CertificateAuthority.objects.init(
   ...   name='child', 
   ...   subject=x509_name('/CN=child.example.com'),
   ...   parent=ca)
   >>> child.parent
   <CertificateAuthority: ca>
   >>> ca.children.all()
   <CertificateAuthorityQuerySet [<CertificateAuthority: child>]>

Or to create a CA with all extensions that live CAs have, you can pass many more
parameters::

   >>> name_constraints = x509.Extension(
   ...     oid=x509.oid.ExtensionOID.NAME_CONSTRAINTS,
   ...     critical=True,
   ...     value=x509.NameConstraints(
   ...         permitted_subtrees=[x509.DNSName('.com')],
   ...         excluded_subtrees=None
   ...     )
   ... )
   >>> full = CertificateAuthority.objects.init(
   ...   name='full', 
   ...   subject=x509_name('/CN=full.example.com'),
   ...   parent=ca,  # some extensions are only valid for intermediate CAs
   ...   issuer_url='http://full.example.com/full.der',
   ...   # this CA can only sign for *.com domains:
   ...
   ...   # CRL/OCSP URLs for signed certificates. These can be changed later:
   ...   crl_url=['http://full.example.com/full.crl', ],
   ...   ocsp_url='http://full.example.com/ocsp',
   ...
   ...   # CRL/OCSP/Issuer URLs for the CA. These are only meaningful for
   ...   # intermediate CAs:
   ...   ca_crl_url=['http://parent.example.com/parent.crl', ],
   ...   ca_ocsp_url='http://parent.example.com/ocsp',
   ...   ca_issuer_url='http://parent.example.com/parent.crt',
   ...   extra_extensions=[name_constraints]
   ... )

There are some more parameters to configure how the CA will be signed::

   >>> from cryptography.hazmat.primitives.asymmetric import ec
   >>> from cryptography.hazmat.primitives import hashes
   >>> CertificateAuthority.objects.init(
   ...   name='props', 
   ...   subject=x509_name('/CN=child.example.com'),
   ...   algorithm=hashes.SHA256(),  # SHA512 would be the default
   ...   pathlen=3,  # three levels of intermediate CAs allowed,
   ...   password=b'foobar',  # encrypt private key with this password
   ...   key_size=4096,  # key size for DSA/RSA keys - unused in this example
   ...   key_type='ECC',  # create an ECC private key
   ...   ecc_curve=ec.SECP256R1()  # ECC key curve
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
   <builtins.CertificateSigningRequest object at ...>
   >>> from django_ca.models import Certificate
   >>> Certificate.objects.create_cert(csr=csr, ca=ca, subject='/CN=example.com')
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

