##########
Python API
##########

**django-ca** provides a Python API for everyone that wants to extend the functionality or build your own
solution on top.

.. NOTE::

   This project is developed using `Python <https://www.python.org/>`_ and
   `Django <https://www.djangoproject.com/>`_. Using the Python API requires knowledge in both. If you need
   help, both projects provide excellent documentation.

*******
General
*******

**django-ca** is a standard :doc:`Django App <django:ref/applications>`. Using it requires a basic Django
environment. You do not have to provide any special settings, default settings should be fine.

If you plan on using this project in standalone scripts, Django has
:ref:`some hints <django:settings-without-django-settings-module>` to get you started. But note that you still
have to configure all of the basic Django settings and there is virtually no functionality without a database.

In some environments, e.g. where **django-ca** is exclusively used with command-line scripts, it might we
worth it to use the default SQLite database backend.

***********************
Certificate Authorities
***********************

Certificate Authorities are represented by the :py:class:`~django_ca.models.CertificateAuthority` model. It is
a standard Django model, which means you can use the :doc:`QuerySet API <django:ref/models/querysets>` to
retrieve and manipulate CAs::

   >>> from django_ca.models import CertificateAuthority
   >>> ca = CertificateAuthority.objects.get(name='root')
   >>> ca.enabled = False
   >>> ca.save()

To create a new CA, you have to :py:meth:`~django_ca.managers.CertificateAuthorityManager.init`, this example
creates a minimal CA::

   >>> from django_ca.models import CertificateAuthority
   >>> from django_ca.utils import x509_name
   >>> from datetime import datetime
   >>> CertificateAuthority.objects.init(
   ...     name='ca-two', subject=x509_name('/CN=ca.example.com'))
   <CertificateAuthority: ca-two>

Please see :ref:`models-certificate-authority` for a more detailed description on how to handle CAs.

************
Certificates
************

Certificates are represented by the :py:class:`~django_ca.models.Certificate` model, they too are a standard
Django model::

   >>> from django_ca.models import Certificate
   >>> cert = Certificate.objects.get(serial=cert_serial)
   >>> cert.revoke()  # this already calls save()

Much like with certificate authorities, creating a new certificate requires a manager method,
:py:func:`Certificate.objects.create_cert() <django_ca.managers.CertificateManager.create_cert>`::

   >>> from django_ca.utils import x509_name
   >>> Certificate.objects.create_cert(ca, csr, subject=x509_name('/CN=example.com'))
   <Certificate: example.com>

***********************
Subjects and Extensions
***********************

**django-ca** provides a set of convenience classes to allow you to handle subjects and extensions for
certificates more easily. These classes are easy to instantiate and provide convenient access methods:

* :py:class:`django_ca.subject.Subject` handles x509 subjects, e.g. as used in a certificate subject.
* :py:class:`django_ca.extensions` is a module that includes various classes that represent x509 extensions.

Both certificate authorities and certificates have many common extensions available as properties::

   >>> ca.key_usage
   <KeyUsage: ['cRLSign', 'keyCertSign'], critical=True>
   >>> ca.basic_constraints
   <BasicConstraints: ca=True, pathlen=None, critical=True>

*******
Signals
*******

Signals are a way for a developer to execute code whenever an event happens, for example to send out an email
whenever a new certificate is issued. **django-ca** provides some :doc:`custom signals </signals>`.
