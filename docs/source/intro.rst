**django-ca** is a tool to manage TLS certificate authorities and easily issue and revoke certificates. It is
based `cryptography <https://cryptography.io/>`_ and `Django <https://www.djangoproject.com/>`_. It can be
used as an app in an existing Django project or stand-alone with the basic project included. Everything can be
managed via the command line via `manage.py` commands - so no web server is needed, if you’re happy with the
command-line.

Features:

1. Set up a secure local certificate authority in just a few minutes.
2. Certificate revocation via CRLs and OCSP.
3. Preliminary ACMEv2 support.
4. Written in Python 3.6+, Django 2.2+ and cryptography 2.8+.
5. Management via command line and/or via Djangos admin interface.
6. Get email notifications about certificates about to expire.
