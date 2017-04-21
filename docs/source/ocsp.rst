####################
Run a OCSP responder
####################

OCSP, or the `Online Certificate Status Protocol
<https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol>`_ provides a
second method (besides :doc:`CRLs <crl>`) for a client to find out if a
certificate has been revoked.

.. WARNING::

   The OCSP responder included in **django-ca** is still very experimental. Expect problems when
   using it. Please also expect major changes in how it is configured in future versions.

*****************************
Configure OCSP with django-ca
*****************************

**django-ca** provides generic HTTP endpoints for an OCSP service for your certificate authorities.
The setup involves:

#. :ref:`Creating a responder certificate <create-ocsp-cert>`
#. :ref:`Configure generic views <ocsp-generic-views>`
#. :ref:`Add a OCSP URL to the new certificate <add-ocsp-url>`

.. versionadded:: 1.2
   Before version 1.2, django-ca was not able to host its own OCSP responder.

.. _create-ocsp-cert:

Create an OCSP responser certificate
====================================

To run an OCSP responder, you first need a certificate with some special
properties. Luckily, **django-ca** has a profile predefined for you:

.. code-block:: console

   $ openssl genrsa -out ocsp.key 4096
   $ openssl req -new -key ocsp.key -out ocsp.csr -utf8 -batch
   $ python manage.py sign_cert --csr=ocsp.csr --out=ocsp.pem \
   >     --subject /CN=ocsp.example.com --ocsp

.. WARNING::

   The CommonName in the certificates subject must match the domain where you host your
   **django-ca** installation.

.. _ocsp-generic-views:

Configure generic views
=======================

The final step in configuring an OCSP responder for the CA is configuring the HTTP endpoint. If
you've installed django-ca as a full project or include ``django_ca.urls`` in your root URL config,
configure the ``CA_OCSP_URLS`` setting. It's a dictionary configuring instances of
:py:class:`~django_ca.views.OCSPView`. Keys become part of the URL pattern, the value is a
dictionary for the arguments of the view. For example::

   CA_OCSP_URLS = {
       'root': {
           'ca': '34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F',
           'responder_key': '/usr/share/django-ca/ocsp.key',
           'responder_cert': 'F2:5F:7F:31:E1:91:4F:D7:9A:D4:19:65:17:3D:43:88',
           # optional: How long OCSP responses are valid
           #'expires': 3600,
       },
   }

This would mean that your OCSP responder would be located at ``/django_ca/ocsp/root/`` at whatever
domain you have configured your WSGI daemon. If you're using your own URL configuration, pass the
same parameters to the ``as_view()`` method.

.. autoclass:: django_ca.views.OCSPView
   :members:

.. _add-ocsp-url:

Add OCSP URL to new certificates
================================

To include the URL to an OCSP service to newly issued certificates (you cannot
add it to already issued certificates, obviously), either set it in the admin
interface or via the command line:

.. code-block:: console

   $ python manage.py list_cas
   34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F - Root CA
   $ python manage.py edit_ca --ocsp-url=http://ocsp.example.com/ \
   >     34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F

*******************************************
Run an OCSP responser with ``openssl ocsp``
*******************************************

OpenSSL ships with the ``openssl ocsp`` command that allows you to run an OCSP
responser, but note that the manpage says **"only useful for test and
demonstration purposes"**.

To use the command, generate an index:

.. code-block:: console

   $ python manage.py dump_ocsp_index ocsp.index

OpenSSL itself allows you to run an OCSP responder with this command:

.. code-block:: console

   $ openssl ocsp -index ocsp.index -port 8888 -rsigner ocsp.pem \
   >     -rkey ocsp.example.com.key -CA files/ca.crt -text

