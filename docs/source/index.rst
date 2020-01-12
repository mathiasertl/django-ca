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

1. Set up a secure local certificate authority in just a few minutes.
2. Written in Python 3.5+, Django 2.2+ and cryptography 2.7+.
3. Management via command line and/or via Djangos admin interface.
4. Certificate revocation via CRLs and OCSP.
5. Get email notifications about certificates about to expire


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
   python/profiles
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

