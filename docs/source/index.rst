.. django-ca documentation master file, created by
   sphinx-quickstart on Mon Jan  4 18:57:14 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-ca's documentation!
=====================================

**django-ca** is a small project to manage TLS certificate authorities and easily issue
certificates. It is based on `pyOpenSSL <https://pyopenssl.readthedocs.org/>`_ and `Django
<https://www.djangoproject.com/>`_.  It can be used as an app in an existing Django project or
stand-alone with the basic project included.  Certificates can be managed through Djangos admin
interface or via `manage.py` commands - so no webserver is needed, if you’re happy with the
command-line.

Features:

* Set up a secure local certificate authority in just a few minutes.
* Written in Python2.7/Python3.4+.
* Manage your entire certificate authority from the command line and/or via
  Djangos admin interface.
* Get email notifications about certificates about to expire.
* Support generating for certificate revocation lists (CRLs).
* Generates index files that can be used with the `openssl ocsp` command for a crude OCSP service.

Contents:

.. toctree::
   :maxdepth: 1

   install
   update
   ca_management
   settings
   manage_commands
   crl
   ocsp
   ca_examples
   changelog
   development


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

