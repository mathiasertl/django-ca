.. django-ca documentation master file, created by
   sphinx-quickstart on Mon Jan  4 18:57:14 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-ca's documentation!
=====================================

**django-ca** provides you with a local TLS certificate authority. It is based
on `pyOpenSSL <https://pyopenssl.readthedocs.org/>`_ and `Django
<https://www.djangoproject.com/>`_, it can be used as an app in an existing
Django project or with the basic project included.  Certificates can be managed
through Djangos admin interface or via ``manage.py`` commands - no webserver is
needed, if you're happy with the command-line.

Features:

* Set up a secure local certificate authority in just a few minutes.
* Written in Python3.4+.
* Manage your entire certificate authority from the command line and/or via
  Djangos admin interface.
* Get email notifications about certificates about to expire.
* Support for certificate revocation lists (CRLs) and OCSP (both have to be
  hosted separately).

Contents:

.. toctree::
   :maxdepth: 2

   install
   ca_management
   settings
   manage_commands
   crl
   ocsp
   development


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

