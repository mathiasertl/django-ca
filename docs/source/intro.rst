**django-ca** is a tool to manage TLS certificate authorities and easily issue and revoke certificates. It is
based `cryptography <https://cryptography.io/>`_ and `Django <https://www.djangoproject.com/>`_. It can be
used as an app in an existing Django project or stand-alone with the basic project included. Everything can be
managed via the command line via `manage.py` commands - so no web server is needed, if you’re happy with the
command-line.

Features:

#. Set up a secure local certificate authority in just a few minutes.
#. Certificate issuance via ACMEv2, REST API, command line or web interface.
#. Certificate revocation via CRLs and OCSP.
#. Private key storage on the file system, in the database or in a Hardware Security Module (HSM).
#. Management via command line and/or via Django's admin interface.
#. Get email notifications about certificates about to expire.
#. Written in Python 3.9+, Django 4.2+ and cryptography 43+.

Please see https://django-ca.readthedocs.org for the most recent documentation.
