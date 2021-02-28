####################
Run a OCSP responder
####################

OCSP, or the `Online Certificate Status Protocol
<https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol>`_ provides a
second method (besides :doc:`CRLs <crl>`) for a client to find out if a
certificate has been revoked.

*****************************
Configure OCSP with django-ca
*****************************

If you have (correctly) configured a :ref:`CA_DEFAULT_HOSTNAME <settings-ca-default-hostname>` and setup the
web server under that URL, you do not have to configure anything to run an OCSP responder.

To run the responder you only need to create OCSP responder keys/certificates using a :command:`manage.py`
command:

.. code-block:: console

   $ python manage.py regenerate_ocsp_keys

Note that you need to pass a password if you have a CA where the private key is encrypted. If you have only
some CAs with a password, or you use different passwords, you'll have to generate keys individually:

.. code-block:: console

   $ python manage.py list_cas
   11:22:33 - CA with password foo
   44:55:66 - CA with password bar
   $ python manage.py regenerate_ocsp_keys --password foo 11:22:33
   $ python manage.py regenerate_ocsp_keys --password bar 44:55:66


************
Manual setup
************

**django-ca** provides the generic view :py:class:`~django_ca.views.OCSPView` for an OCSP service for your
certificate authorities. The setup involves:

#. :ref:`Creating a responder certificate <create-ocsp-cert>`
#. :ref:`Configure generic views <ocsp-generic-views>`
#. :ref:`Add a OCSP URL to the new certificate <add-ocsp-url>`

.. _create-ocsp-cert:

Create an OCSP responder certificate
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

The final step in configuring an OCSP responder for the CA is configuring the HTTP endpoint. If you've
installed django-ca as a full project or include ``django_ca.urls`` in your root URL configuration, configure
the ``CA_OCSP_URLS`` setting. It's a dictionary configuring instances of
:py:class:`~django_ca.views.OCSPView`. Keys become part of the URL pattern, the value is a dictionary for the
arguments of the view. For example::

   CA_OCSP_URLS = {
       'root-ca': {
           'responder_key': '/usr/share/django-ca/ocsp.key',
           'responder_cert': '/usr/share/django-ca/ocsp.pem',

           # optional: The name or serial of the CA. By default, the dictionary key ("Root CA" in
           #           this example is assumed to be the CA name or serial.
           #'ca': '34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F',

           # optional: How long OCSP responses are valid
           #'expires': 3600,
       },

       # This URL can be added to any intermediate CA using the --ca-ocsp-url parameter
       'intermediate-ca': {
           # Dictionary key is not the name of the root CA, so we pass a serial instead:
           'ca': '34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F',
           'responder_key': '/usr/share/django-ca/ocsp.key',
           'responder_cert': '/usr/share/django-ca/ocsp.pem',

           # optional: This URL serves OCSP responses for Child CAs, not signed enduser certs:
           #'ca_ocsp': True,
       }
   }

This would mean that your OCSP responder would be located at ``/django_ca/ocsp/root-ca/`` at whatever
domain you have configured your WSGI daemon. If you're using your own URL configuration, pass the
same parameters to the ``as_view()`` method. Please see the the class documentation for possible options:

* :py:class:`django_ca.views.OCSPView`

.. _add-ocsp-url:

Add OCSP URL to new certificates
================================

To include the URL to an OCSP service to newly issued certificates (you cannot add it to already issued
certificates, obviously), either set it in the admin interface or via the command line:

.. code-block:: console

   $ python manage.py list_cas
   34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F - Root CA
   $ python manage.py edit_ca --ocsp-url=http://ocsp.example.com/django_ca/ocsp/root-ca/ \
   >     34:D6:02:B5:B8:27:4F:51:9A:16:0C:B8:56:B7:79:3F

*******************************************
Run an OCSP responder with ``openssl ocsp``
*******************************************

.. deprecated:: 1.18.0

   This function will be removed in django-ca 1.20.0.

.. WARNING::

   The OCSP responder provided by :manpage:`openssl-ocsp(1SSL)` is not a full OCSP responder. The man page
   states explicitly:

       The OCSP server is only useful for test and demonstration purposes: it is not really usable as a full OCSP responder. It contains only
       a very simple HTTP request handling and can only handle the POST form of OCSP queries. It also handles requests serially meaning it
       cannot respond to new requests until it has processed the current one. The text index file format of revocation is also inefficient for
       large quantities of revocation data.

   Thus this functionality will be removed in django-ca 1.20.0.


OpenSSL ships with the ``openssl ocsp`` command that allows you to run an OCSP
responder, but note that the man page says **"only useful for test and
demonstration purposes"**.

To use the command, generate an index:

.. code-block:: console

   $ python manage.py dump_ocsp_index ocsp.index

OpenSSL itself allows you to run an OCSP responder with this command:

.. code-block:: console

   $ openssl ocsp -index ocsp.index -port 8888 -rsigner ocsp.pem \
   >     -rkey ocsp.example.com.key -CA files/ca.crt -text

