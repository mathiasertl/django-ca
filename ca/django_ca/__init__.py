"""Default Django App configuration."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

try:
    __version__ = version("django-ca")
    __release__ = ".".join(__version__.split(".")[:3])
except PackageNotFoundError:
    # Not installed
    __version__ = __release__ = ""

# Path to default Django app configuration
# pylint: disable=invalid-name
# The variable name is a Django standard name
default_app_config = "django_ca.apps.DjangoCAConfig"  # pragma: only django<4.1
