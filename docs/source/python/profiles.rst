#############################################
``django_ca.profiles`` - Certificate profiles
#############################################

The profiles module defines classes and methods for :doc:`handling profiles </profiles>`.

Even if you use the Python API, you do not need to handle any instances from this module directly in most
cases.  Instead, you can simply pass a name of the profile instead. For example, to create a certificate using
the ``webserver`` profile::

   # Note: "csr" is a predefined variable, see https://cryptography.io/en/latest/x509/tutorial/
   >>> from cryptography import x509
   >>> from cryptography.x509.oid import NameOID
   >>> from django_ca.key_backends.storages import StoragesUsePrivateKeyOptions
   >>> from django_ca.models import Certificate
   >>> from django_ca.profiles import profiles
   >>> subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
   >>> key_backend_options = StoragesUsePrivateKeyOptions(password=None)
   >>> Certificate.objects.create_cert(
   ...    ca, key_backend_options, csr, profile=profiles['webserver'], subject=subject
   ... )
   <Certificate: example.com>

But you can also create your own profile manually to create a special type of certificate::

   >>> from django_ca.models import CertificateAuthority
   >>> profile = Profile(
   ...     'example',
   ...     subject=x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, 'AT')]),
   ...     extensions={'ocsp_no_check': {}}
   ... )
   >>> ca = CertificateAuthority.objects.first()
   >>> profile.create_cert(ca, key_backend_options, csr, subject=subject)
   <Certificate(subject=<Name(C=AT,CN=example.com)>, ...)>


.. autoclass:: django_ca.profiles.Profile
   :members:
