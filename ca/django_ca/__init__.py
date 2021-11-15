"""Default Django App configuration."""

import sys

if sys.version_info >= (3, 8):  # pragma: only py>=3.8
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version
else:  # pragma: only py<3.8
    from importlib_metadata import PackageNotFoundError
    from importlib_metadata import version


try:  # pragma: no cover
    __version__ = version("django-ca")
    __release__ = ".".join(__version__.split(".")[:3])
except PackageNotFoundError:  # pragma: no cover
    # django-ca is not installed (e.g. running from a git clone)
    __version__ = __release__ = ""

# Path to default Django app configuration
# pylint: disable=invalid-name
# The variable name is a Django standard name
default_app_config = "django_ca.apps.DjangoCAConfig"  # pragma: only django<4.1
