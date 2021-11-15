"""Default Django App configuration."""

# WARNING: This module MUST NOT include any external dependencies, as it is read by setup.py

try:
    # created by setuptools_scm
    from ._version import version as __version__
    from ._version import version_tuple as VERSION
except ImportError:
    __version__ = VERSION = ""

# Path to default Django app configuration
# pylint: disable=invalid-name
# The variable name is a Django standard name
default_app_config = "django_ca.apps.DjangoCAConfig"  # pragma: only django<4.1
