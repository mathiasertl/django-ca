#############################################
``django_ca.profiles`` - Certificate profiles
#############################################

The profiles module defines classes and methods for :doc:`handling profiles </profiles>`.

Even if you use the Python API, you do not need to handle any instances from this module directly in most
cases.  Instead, you can simply pass a name of the profile instead. For example, to create a certificate using
the ``webserver`` profile::

   # Note: "csr" is a predefined variable, see https://cryptography.io/en/latest/x509/tutorial/
   >>> from django_ca.models import Certificate
   >>> Certificate.objects.create_cert(ca, csr, 'webserver', subject='/CN=example.com')
   <Certificate: example.com>

But you can also create your own profile manually to create a special type of certificate::

   >>> from django_ca.models import CertificateAuthority
   >>> profile = Profile('example', subject='/C=AT', extensions={'ocsp_no_check': {}})
   >>> ca = CertificateAuthority.objects.first()
   >>> profile.create_cert(ca, csr, subject='/CN=example.com')
   <Certificate(subject=<Name(C=AT,CN=example.com)>, ...)>

You can also access profiles using ``profiles.profiles``, create a copy and update the copy::

   >>> from django_ca.profiles import profiles
   >>> profile = profiles['webserver'].copy()
   >>> cert = Certificate.objects.create_cert(ca, csr, profile=profile, subject='/CN=example.com')
   >>> cert.subject_alternative_name
   <SubjectAlternativeName: ['DNS:example.com'], critical=False>
   >>> profile.cn_in_san = False
   >>> cert = Certificate.objects.create_cert(ca, csr, profile=profile, subject='/CN=example.com')
   >>> cert.subject_alternative_name is None
   True

.. autoclass:: django_ca.profiles.Profile
   :members:
