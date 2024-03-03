#######
Testing
#######

**django-ca** uses `pytest <https://docs.pytest.org/>`_ for running the test suite:

.. code-block:: console

   $ pytest -v

This will generate a code coverage report in ``docs/build/html/``.

*************
Test coverage
*************

The test suite must ensure 100% test coverage. Completely excluding code from test coverage is only allowed
when absolutely necessary.

Conditional pragmas
===================

In addition to the standard ``# pragma: no cover`` and ``# pragma: no branch``, the test suite adds pragmas to
exclude code based on the Python version or library versions. For example::

   if sys.version_info >= (3, 8):  # pragma: only py>=3.8
      from typing import Literal
   else:  # pragma: only py<3.8
      from typing_extensions import Literal

If you have branches that are only relevant for some versions, there's also pragmas for that::

   if sys.version_info >= (3, 8):  # pragma: py>=3.8 branch
      print("Do something that's only useful in Python 3.8 or newer.")
   if django.VERSION[:2] >= (3, 2):  # pragma: django>=3.2 branch
      print("Do something that's only useful in Django 3.2 or newer.")

You can use all operators (``<``, ``<=``, ``==``, ``!=``, ``>``, ``>=``), and we add pragma for the versions
of Python, Django, cryptography.

Please check :file:`ca/django_ca/tests/base/pragmas.py` for a tested file that includes all supported pragmas.
Correctly using the pragmas is mandatory, as they are also used for finding outdated code when older versions
are deprecated.

******
pytest
******

Fixtures
========

.. autofunction:: django_ca.tests.conftest.ca_name

.. autofunction:: django_ca.tests.conftest.hostname

.. autofunction:: django_ca.tests.conftest.key_backend

.. autofunction:: django_ca.tests.conftest.rfc4514_subject

.. autofunction:: django_ca.tests.conftest.subject

.. autofunction:: django_ca.tests.conftest.tmpcadir

.. autofunction:: django_ca.tests.conftest.usable_ca

.. autofunction:: django_ca.tests.conftest.usable_cas

.. autofunction:: django_ca.tests.conftest.usable_cert

Generated fixtures
------------------

{name}_pub - :py:class:`~cryptography.x509.Certificate`
    Certificate loaded from test fixture data.

    Available for every CA generated in the test fixtures and every certificate (including unusable
    certificates). Examples: ``root_pub``, ``root_cert``, ``profile_server_pub`` and
    ``globalsign_dv-cert_pub``.

{ca_name} - :py:class:`~django_ca.models.CertificateAuthority`
    Certificate authority model **without** usable private key files.

    Available for every CA generated in the test fixtures. Using this fixture enables database access.

usable_{ca_name} - :py:class:`~django_ca.models.CertificateAuthority`
    Certificate authority model with usable private key files.

    Available for every CA generated in the test fixtures.

{cert} - :py:class:`~django_ca.models.Certificate`
    Certificate model for certificates generated in test fixture data.

Mocks
=====

.. automodule:: django_ca.tests.base.mocks
   :members:

Assertions
==========

.. automodule:: django_ca.tests.base.assertions
   :members:

Admin interface
---------------

.. automodule:: django_ca.tests.admin.assertions
   :members:


Utility functions
=================

.. automodule:: django_ca.tests.base.utils
   :members:
   :exclude-members: OutputChecker
