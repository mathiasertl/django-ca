################
Coding standards
################

This document describes the coding standards used in this project.

.. NOTE::

   Just want to run all quality checks and tests? See :ref:`testing-checklist` below.

*******
Linters
*******

**django-ca** is linted and formatted with the following formatters:

* `isort <https://pycqa.github.io/isort/>`_
* `flake8 <https://flake8.pycqa.org/en/latest/>`_
* `black <https://black.readthedocs.io/en/stable/>`_
* `pylint <https://github.com/PyCQA/pylint>`_

To test all linters, simply run (:command:`pylint` is separate for now, as it is very slow):

.. code-block:: console

   $ ./dev.py code-quality
   $ pylint ca/django_ca/

**********
Type hints
**********

The source code also uses type hints and is checked using `mypy <https://mypy.readthedocs.io/en/stable/>`_.
At present (2021-05-15), the latest version cryptography (3.4.7) does not have full type hints. Until
cryptography 35.0 is released, you have to install the latest version from git:

.. code-block:: console

   $ pip install -U git+https://github.com/pyca/cryptography.git
   $ mypy ca/django_ca/

*********
Overrides
*********

isort, flake8, pylint and mypy support overriding warnings. If necessary, follow these general rules:

* Use overrides as rarely as possible.
* Exclude specific errors (so e.g. for flake8, use ``# NOQA: E501`` instead of ``# NOQA``).
* Add comments explaining the exclude. If possible, comment in the same line::

      import unused  # NOQA: F401  # Import this for some important reason

  If your comment does not fit in the same line, add a comment above prefixed with ``$SW NOTE:``::

      # PYLINT NOTE: A really long explanation why we have the bar argument that is not used.
      # TYPE NOTE: We don't type this, since it's only a demo.
      def func(foo, bar):  # type: ignore # pylint: disable=unused-argument
          """Comment to make pylint happy."""
          print(foo)

*************
Documentation
*************

Documentation is checked using `doc8 <https://github.com/pycqa/doc8>`_ and spell checked using
`sphinxcontrib.spelling <https://sphinxcontrib-spelling.readthedocs.io/en/latest/index.html>`_.

.. code-block:: console

   $ doc8 docs/source/
   $ make -C docs spelling

Warnings are always turned into errors, as this uncovers various mistakes such as broken references. To build
the documentation, simply run:

.. code-block:: console

   $ make -C docs html

***
tox
***

To run all checkers with `tox <https://tox.readthedocs.io/en/latest/>`_, simply run:

.. code-block:: console

   $ tox -e lint,pylint,mypy,docs,dist-test

Note that pylint (currently) runs for an extremely long time.

*************
Test coverage
*************

The test suite must ensure 100% test coverage. Completely excluding code from test coverage is only allowed
when absolutely necessary. To generate a coverage report in :file:`docs/build/coverage/`, simply run:

.. code-block:: console

   $ ./dev.py coverage

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
are deprecated.a

.. _testing-checklist:

*****************
Testing checklist
*****************

The following commands, assuming you have a virtualenv active, run all linters, test code coverage and check
documentation (note that pylint currently takes a long time).

.. code-block:: console

   $ tox -e lint,pylint,mypy,docs,dist-test
   $ ./dev.py coverage
