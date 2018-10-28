.. django-ca documentation master file, created by
   sphinx-quickstart on Mon Jan  4 18:57:14 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-ca's documentation!
=====================================

**django-ca** is a tool to manage TLS certificate authorities and easily issue and revoke certificates. It is
based `cryptography <https://cryptography.io/>`_ and `Django <https://www.djangoproject.com/>`_. It can be
used as an app in an existing Django project or stand-alone with the basic project included. Everything can be
managed via the command line via `manage.py` commands - so no webserver is needed, if you’re happy with the
command-line.

Features:

* Create certificate authorities, issue and revoke certificates in minutes.
* Receive e-mail notifications of certificates about to expire.
* Certificate validation via the included OCSP responder and Certificate Revocation Lists (CRLs).
* Complete, consistent and powerful command line interface.
* Optional web interface for certificate handling (e.g. issuing, revoking, ...).
* Written in pure Python2.7/Python3.4+, using Django 1.11 or later.

Installation/Configuration:

.. toctree::
   :maxdepth: 1

   install
   docker
   update
   changelog
   settings

Usage:

.. toctree::
   :maxdepth: 1

   cli/intro
   Command-line interface: certificate authority management <cli/cas>
   Command-line interface: certificate management <cli/certs>
   web_interface
   crl
   ocsp

Python API:

.. toctree::
   :maxdepth: 1

   Introduction <python/intro>
   signals
   python/extensions
   python/models
   python/subject
   python/utils


Development documentation:

.. toctree::
   :maxdepth: 1

   development
   contribute
   release
   ca_examples
   extensions


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

