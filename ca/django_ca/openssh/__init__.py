"""Module collecting support classes for OpenSSH CA support."""

from .constants import OpenSshCertificateType
from .extensions import SshHostCaExtension
from .extensions import SshHostCaType
from .extensions import SshUserCaExtension
from .extensions import SshUserCaType

__all__ = (
    "OpenSshCertificateType",
    "SshHostCaType",
    "SshHostCaExtension",
    "SshUserCaType",
    "SshUserCaExtension",
)
