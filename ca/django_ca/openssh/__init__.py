"""Module collecting support classes for OpenSSH CA support."""

from django_ca.openssh.constants import OpenSshCertificateType
from django_ca.openssh.extensions import SshHostCaExtension, SshHostCaType, SshUserCaExtension, SshUserCaType

__all__ = (
    "OpenSshCertificateType",
    "SshHostCaType",
    "SshHostCaExtension",
    "SshUserCaType",
    "SshUserCaExtension",
)
