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

     python setup.py code_quality

Naturally, I also expect the test suite to still pass. Please make sure you test
in at least your local Python2 and Python3 environments::

     python setup.py test

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

Generate a coverage report and make sure that your code is covered by tests.

.. WARNING::

   Code coverage is not a catch all tool for "yes, this code is well-tested".
   It's a tool to catch missed spots, but you must still think for yourself
   about what and how to test.
