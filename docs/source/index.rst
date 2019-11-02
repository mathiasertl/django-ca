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
* Written in pure Python2.7/Python3.5+, using Django 1.11 or later.

.. toctree::
   :maxdepth: 1
   :caption: Installation

   install
   docker
   update
   changelog
   settings

.. toctree::
   :maxdepth: 1
   :caption: Usage

   cli/intro
   Command-line interface: certificate authority management <cli/cas>
   Command-line interface: certificate management <cli/certs>
   web_interface
   profiles
   crl
   ocsp

.. toctree::
   :maxdepth: 1
   :caption: Python API

   Introduction <python/intro>
   signals
   python/extensions
   python/models
   python/subject
   python/utils


.. toctree::
   :maxdepth: 1
   :caption: Development

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

