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


.. automodule:: django_ca.tests.base.fixtures
   :members:


Generated fixtures
------------------

`{name}_pub` - :py:class:`~cryptography.x509.Certificate`
    Certificate loaded from test fixture data.

    Available for every CA generated in the test fixtures and every certificate. Examples: ``root_pub``,
    ``root_cert_pub``, ``profile_server_pub``. Contributed certificates are prefixed with ``contrib_``
    (see below).

`{ca_name}` - :py:class:`~django_ca.models.CertificateAuthority`
    Certificate authority model **without** usable private key files.

    Available for every CA generated in the test fixtures. Using this fixture enables database access.

`{cert}` - :py:class:`~django_ca.models.Certificate`
    Certificate model for certificates generated in test fixture data.

`contrib_{ca_name}` - :py:class:`~django_ca.models.CertificateAuthority`
    Certificate authority model for a contributed certificate.

    Examples: ``contrib_geotrust`` and ``contrib_startssl_class3``.

`contrib_{ca_name}_cert` - :py:class:`~django_ca.models.Certificate`
    Certificate model for contributed certificates loaded from test fixture data.

    Examples: ``contrib_geotrust_cert`` and
    ``contrib_startssl_class3_cert``.

`contrib_{ca_name}_cert_pub` - :py:class:`~cryptography.x509.Certificate`
    Certificate for contributed certificates loaded from test fixture data.

    Examples: ``contrib_geotrust_cert_pub`` and
    ``contrib_startssl_class3_cert_pub``.

`contrib_{ca_name}_pub` - :py:class:`~cryptography.x509.Certificate`
    Certificate for contributed certificate authorities loaded from test fixture data.

    Examples: ``contrib_geotrust_pub`` and ``contrib_startssl_class3_pub``.

`usable_{ca_name}` - :py:class:`~django_ca.models.CertificateAuthority`
    Certificate authority model with usable private key files.

    Available for every CA generated in the test fixtures.

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


********
Doctests
********

:py:mod:`django_ca.tests.base.doctest` provides helper functions for testing doctests.

Functions in this module use a custom OutputChecker to enable the ``STRIP_WHITESPACE`` doctest option. This
option will remove all whitespace (including newlines) from the both actual and expected output. It can be
used for formatting actual output with newlines to improve readability. For example::

    >>> from cryptography import x509
    >>> from cryptography.x509.oid import ExtensionOID
    >>> x509.Extension(
    ...     oid=ExtensionOID.BASIC_CONSTRAINTS,
    ...     critical=True,
    ...     value=x509.BasicConstraints(ca=False, path_length=None)
    ... )  # doctest: +STRIP_WHITESPACE
    <Extension(
        oid=<ObjectIdentifier(oid=2.5.29.19, name=basicConstraints)>,
        critical=True,
        value=<BasicConstraints(ca=False, path_length=None)>
    )>

Use :py:func:`django_ca.tests.base.doctest.doctest_module` to test a Python module::

    def test_doctests() -> None:
        """Run doctests for this module."""
        failures, _tests = doctest_module("django_ca.pydantic.name")
        assert failures == 0, f"{failures} doctests failed, see above for output."

.. automodule:: django_ca.tests.base.doctest
   :members:
   :exclude-members: OutputChecker
