"""Module collecting support classes for OpenSSH CA support."""

from .constants import OpenSshCertificateType
from .extensions import SshHostCaType
from .extensions import SshHostCaExtension
from .extensions import SshUserCaType
from .extensions import SshUserCaExtension


__all__ = (
    "OpenSshCertificateType",
    "SshHostCaType",
    "SshHostCaExtension",
    "SshUserCaType",
    "SshUserCaExtension",
)
