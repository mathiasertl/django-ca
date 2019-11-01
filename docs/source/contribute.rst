##########
Contribute
##########

Please also see :doc:`development` for how to setup a development environment.

To contribute to **django-ca** simply do a fork on `on github
<https://github.com/mathiasertl/django-ca>`_ and submit a pull request when
you're happy.

When doing a pull request, please make sure to explain what your improvement
does or what bug is fixed by it and how to reproduce this locally.

************
Code quality
************

This project is very rigorous about code quality standards. That means that the
source code is checked with `Flake8 <http://flake8.pycqa.org/en/latest/>`_ and
import order is checked with `isort <http://isort.readthedocs.io/en/latest/>`_.
Before you submit a pull request, please make sure that all tests pass by
executing::

     python dev.py code-quality

Naturally, I also expect the test suite to still pass. Please make sure you test
in at least your local Python2 and Python3 environments::

     python dev.py test

***********
Write tests
***********

Please write tests for any new functionality. If you provide a bugfix, write a
test that tests the fix, which means that the test should fail on current
master and pass on your pull request.

If a function is also covered with doctests, please consider adding an example
there as well, if it affects handling a parameter or something.

*************
Code coverage
*************

Generate a coverage report and make sure that your code is covered by tests::

     python dev.py coverage

.. WARNING::

   Code coverage is not a catch all tool for "yes, this code is well-tested".
   It's a tool to catch missed spots, but you must still think for yourself
   about what and how to test.

Exclude code
============

The test suite fails if the code coverage is not 100%. But sometimes code is
specific to a particular Python/Django/cryptography version and the code just
never executed when using a different version.

You can exclude code that is just for Python2 or Python3 using comments::
   
   import six

   if six.PY3:  # pragma: only py3
      print('will only be executed on Python 3!')
   else:  # pragma: only py2
      print('will only be executed on Python 2!')

More fine grained pragmas for Python, Django and cryptography versions are also
available::

   if hasattr(ExtensionOID, 'PRECERT_POISON'):  # pragma: cryptography>=2.7
      print('PrecertPoison extension was added in cryptography 2.7')
   else:  # pragma: cryptography<2.7
      print('sorry, no precert poison!')

Sometimes you have code to check for the availability of a feature, but there is
no "else" branch in case the feature doesn't exist. In this case you want to
*exclude* the code if the feature is not available, but want to mark it as *no
branch* if the feature is availalable. For example, the ``source`` attribute was
added to warning messages in Python 3.6::

   if hasattr(msg, 'source'):  # pragma: no branch, pragma: only py>=3.6
      self.assertEqual(data.get('source'), msg.source) 

   if hasattr(msg, 'source'):  # pragma: no branch, pragma: only py>3.5
      print('equivalent to the above.')
