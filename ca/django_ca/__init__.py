"""Default Django App configuration."""
# WARNING: This module MUST NOT include any dependencys, as it is read by setup.py

# https://www.python.org/dev/peps/pep-0440/
# https://www.python.org/dev/peps/pep-0396/
# https://www.python.org/dev/peps/pep-0386/
VERSION = (1, 17, 1)

# __version__ specified in PEP 0396, but we use PEP 0440 format instead of PEP 0386.
__version__ = '1.17.1'

# Path to default Django app configuration
# pylint: disable=invalid-name
# The variable name is a Django standard name
default_app_config = 'django_ca.apps.DjangoCAConfig'
