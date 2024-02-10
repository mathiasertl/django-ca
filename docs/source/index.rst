.. django-ca documentation master file, created by
   sphinx-quickstart on Mon Jan  4 18:57:14 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to django-ca's documentation!
=====================================

.. include:: intro.rst

.. toctree::
   :maxdepth: 1
   :caption: Installation

   install
   update
   changelog
   settings

.. toctree::
   :maxdepth: 1
   :caption: Quickstart

   ... as Django app <quickstart_as_app>
   ... from source <quickstart_from_source>
   ... with Docker <docker>
   ... with Docker Compose <quickstart_docker_compose>

.. toctree::
   :maxdepth: 1
   :caption: Usage

   cli/intro
   Command-line interface: certificate authority management <cli/cas>
   Command-line interface: certificate management <cli/certs>
   web_interface
   acme
   rest_api
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
   python/views
   python/utils
   python/constants
   python/acme_messages
   python/pydantic
   python/tasks
   python/typehints

.. toctree::
   :maxdepth: 1
   :caption: Development

   /dev/contribute
   /dev/testing
   /dev/standards
   /dev/tips
   /dev/acme
   /dev/release
   ca_examples
   extensions


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
