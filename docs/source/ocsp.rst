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

OCSP with docker compose
========================

If you use the :doc:`docker compose <quickstart/docker_compose>`, the setup already provides OCSP services
for all issued certificates.

OCSP with other setups
======================

If your setup does *not* run with a Celery task broker, you need to automatically regenerate the OCSP
certificates e.g. once a day. To regenerate them, you only need to keys/certificates using a
:command:`manage.py` command:

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
certificate authorities. This allows for special OCSP services with "unusual" settings, but is
usually not needed, the default setup should do just fine.

The setup involves:

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
   >     --subject-format=rfc4514 --subject CN=ocsp.example.com --ocsp

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
