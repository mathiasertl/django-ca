################
Coding standards
################

**django-ca** uses linting and type hints to ensure consistent and readable code. It uses `ruff
<https://docs.astral.sh/ruff/>`_ and `pylint <https://github.com/PyCQA/pylint>`_ for linting and `mypy
<https://mypy.readthedocs.io/en/stable/>`_ for type checking. YAML, JSON and TOML files are checked using
`pre-commit <https://pre-commit.com/>`_. Sphinx documentation is checked using `doc8
<https://github.com/pycqa/doc8>`_ and spell-checked using `sphinxcontrib.spelling
<https://sphinxcontrib-spelling.readthedocs.io/en/latest/index.html>`_.

If you have `tox <https://tox.wiki/en/latest/>`_ installed, you can perform all checks by running it with
these environments:

.. code-block:: console

   $ tox -e lint,pylint,mypy,docs

*********
Overrides
*********

ruff, pylint and mypy support overriding warnings. Follow these general rules:

* Use overrides as rarely as possible.
* Exclude specific errors (so e.g. use ``# NOQA: E501`` instead of ``# NOQA``).
* Add a comment explaining the exclude. If possible, comment in the same line::

      import unused  # NOQA: F401  # Import this for some important reason

  If your comment does not fit in the same line, add a comment above prefixed with ``$SW NOTE:``::

      # PYLINT NOTE: A really long explanation why we have the bar argument that is not used.
      # TYPE NOTE: We don't type this, since it's only a demo.
      def func(foo, bar):  # type: ignore # pylint: disable=unused-argument
          """Comment to make pylint happy."""
          print(foo)

******************
Type hints imports
******************

The code generally imports the typing module as a whole, with the most common types imported directly to
increase readability. The following types should be imported directly: ``Any``, ``Dict``, ``Iterable``,
``Iterator``, ``List``, ``Optional``, ``Tuple`` and ``Type``, ``Union``.

Thus::

   import typing  # for most (but rarer) types
   from typing import List, Optional, Any

********************
Manually run linters
********************

To run all linters, simply run (:command:`pylint` runs separate as it is very slow):

.. code-block:: console

   $ ./dev.py code-quality
   $ pylint ca/ca/ ca/django_ca/ devscripts/ docs/source/django_ca_sphinx/ *.py

For type-checking, run:

.. code-block:: console

   $ mypy .

To check the documentation, run:

.. code-block:: console

   $ doc8 docs/source/
   $ make -C docs clean spelling html

