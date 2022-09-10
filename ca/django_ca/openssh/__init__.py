"""Module collecting support classes for OpenSSH CA support."""

from .constants import OpenSshCertificateType
from .extensions import SshHostCaExtension, SshHostCaType, SshUserCaExtension, SshUserCaType

__all__ = (
    "OpenSshCertificateType",
    "SshHostCaType",
    "SshHostCaExtension",
    "SshUserCaType",
    "SshUserCaExtension",
)
