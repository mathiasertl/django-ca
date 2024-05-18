# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Keep track of internal settings for django-ca."""

import os
import typing
from datetime import timedelta
from typing import Any, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID

from django.conf import global_settings, settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

# IMPORTANT: Do **not** import anything but django_ca.constants/deprecation here, or you risk circular
# imports.
from django_ca import constants

if typing.TYPE_CHECKING:
    from django_ca.typehints import AllowedHashTypes, HashAlgorithms


def _check_name(name: x509.Name, hint: str) -> None:
    # WARNING: This function is a duplicate of the function in utils.

    multiple_oids = (NameOID.DOMAIN_COMPONENT, NameOID.ORGANIZATIONAL_UNIT_NAME, NameOID.STREET_ADDRESS)

    seen = set()

    for attr in name:
        oid = attr.oid

        # Check if any fields are duplicate where this is not allowed (e.g. multiple CommonName fields)
        if oid in seen and oid not in multiple_oids:
            raise ImproperlyConfigured(
                f'{hint} contains multiple "{constants.NAME_OID_NAMES[attr.oid]}" fields.'
            )
        seen.add(oid)

        if oid == NameOID.COMMON_NAME and not attr.value:
            raise ImproperlyConfigured(f"{hint}: CommonName must not be an empty value.")


def _normalize_x509_name(value: Any, hint: str) -> Optional[x509.Name]:
    if value is None or isinstance(value, x509.Name):
        return value
    if not isinstance(value, (tuple, list)):
        raise ImproperlyConfigured(f"{hint}: {value}: Value must be an x509.Name, list or tuple.")

    name_attributes: list[x509.NameAttribute] = []
    for elem in value:
        if isinstance(elem, x509.NameAttribute):
            name_attributes.append(elem)
        elif isinstance(elem, (tuple, list)):
            if len(elem) != 2:
                raise ImproperlyConfigured(
                    f"{hint}: {elem}: Must be lists/tuples with two items, got {len(elem)}."
                )
            if not isinstance(elem[1], str):
                raise ImproperlyConfigured(f"{hint}: {elem[1]}: Item values must be strings.")

            name_oid = _normalize_name_oid(elem[0])
            name_attribute = x509.NameAttribute(oid=name_oid, value=elem[1])
            name_attributes.append(name_attribute)
        else:
            raise ImproperlyConfigured(f"{hint}: {elem}: Items must be a x509.NameAttribute, list or tuple.")

    if not name_attributes:
        return None

    normalized_name = x509.Name(name_attributes)
    _check_name(normalized_name, hint)
    return normalized_name


def _normalize_name_oid(value: Any) -> x509.ObjectIdentifier:
    """Normalize str to x509.NameOID."""
    if isinstance(value, x509.ObjectIdentifier):
        return value
    if isinstance(value, str):
        try:
            return constants.NAME_OID_TYPES[value]
        except KeyError as kex:
            try:
                return x509.ObjectIdentifier(value)
            except ValueError as vex:
                raise ImproperlyConfigured(f"{kex.args[0]}: Unknown attribute type.") from vex

    raise ImproperlyConfigured(f"{value}: Must be a x509.ObjectIdentifier or str.")


def _get_hash_algorithm(setting: str, default: "HashAlgorithms") -> "AllowedHashTypes":
    raw_value: "HashAlgorithms" = getattr(settings, setting, default)
    try:
        return constants.HASH_ALGORITHM_TYPES[raw_value]()
    except KeyError as ex2:
        raise ImproperlyConfigured(f"{setting}: {raw_value}: Unknown hash algorithm.") from ex2


CA_PROFILES: dict[str, dict[str, Any]] = {
    "client": {
        # see: http://security.stackexchange.com/questions/68491/
        "description": _("A certificate for a client."),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "digitalSignature",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "clientAuth",
                ],
            },
        },
    },
    "server": {
        "description": _("A certificate for a server, allows client and server authentication."),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "digitalSignature",
                    "keyAgreement",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "clientAuth",
                    "serverAuth",
                ],
            },
        },
    },
    "webserver": {
        # see http://security.stackexchange.com/questions/24106/
        "description": _("A certificate for a webserver."),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "digitalSignature",
                    "keyAgreement",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "serverAuth",
                ],
            },
        },
    },
    "enduser": {
        # see: http://security.stackexchange.com/questions/30066/
        "description": _(
            "A certificate for an enduser, allows client authentication, code and email signing."
        ),
        "extensions": {
            "key_usage": {
                "critical": True,
                "value": [
                    "dataEncipherment",
                    "digitalSignature",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "critical": False,
                "value": [
                    "clientAuth",
                    "codeSigning",
                    "emailProtection",
                ],
            },
        },
    },
    "ocsp": {
        "description": _("A certificate for an OCSP responder."),
        "add_ocsp_url": False,
        "autogenerated": True,
        "subject": False,
        "extensions": {
            "key_usage": {
                "value": [
                    "nonRepudiation",
                    "digitalSignature",
                    "keyEncipherment",
                ],
            },
            "extended_key_usage": {
                "value": [
                    "OCSPSigning",
                ],
            },
            "ocsp_no_check": {},
        },
    },
}

_CA_DEFAULT_SUBJECT = getattr(settings, "CA_DEFAULT_SUBJECT", None)
CA_DEFAULT_SUBJECT: Optional[x509.Name] = _normalize_x509_name(_CA_DEFAULT_SUBJECT, "CA_DEFAULT_SUBJECT")

_CA_DEFAULT_NAME_ORDER = (
    x509.NameOID.DN_QUALIFIER,
    x509.NameOID.COUNTRY_NAME,
    x509.NameOID.POSTAL_CODE,
    x509.NameOID.STATE_OR_PROVINCE_NAME,
    x509.NameOID.LOCALITY_NAME,
    x509.NameOID.DOMAIN_COMPONENT,
    x509.NameOID.ORGANIZATION_NAME,
    x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
    x509.NameOID.TITLE,
    x509.NameOID.COMMON_NAME,
    x509.NameOID.USER_ID,
    x509.NameOID.EMAIL_ADDRESS,
    x509.NameOID.SERIAL_NUMBER,
)
CA_DEFAULT_NAME_ORDER: tuple[x509.ObjectIdentifier, ...] = getattr(
    settings, "CA_DEFAULT_NAME_ORDER", _CA_DEFAULT_NAME_ORDER
)
if not isinstance(CA_DEFAULT_NAME_ORDER, (list, tuple)):
    raise ImproperlyConfigured("CA_DEFAULT_NAME_ORDER: setting must be a tuple.")
CA_DEFAULT_NAME_ORDER = tuple(_normalize_name_oid(name_oid) for name_oid in CA_DEFAULT_NAME_ORDER)

# Add ability just override/add some profiles
CA_DEFAULT_PROFILE = getattr(settings, "CA_DEFAULT_PROFILE", "webserver")

_CA_PROFILE_OVERRIDES = getattr(settings, "CA_PROFILES", {})
for profile_name, profile in _CA_PROFILE_OVERRIDES.items():
    if profile is None:
        del CA_PROFILES[profile_name]
        continue

    if profile_name in CA_PROFILES:
        CA_PROFILES[profile_name].update(profile)
    else:
        CA_PROFILES[profile_name] = profile

for profile_name, profile in CA_PROFILES.items():
    profile.setdefault("subject", CA_DEFAULT_SUBJECT)

    if subject := profile.get("subject"):
        profile["subject"] = _normalize_x509_name(subject, f"subject in {profile_name} profile.")

if CA_DEFAULT_PROFILE not in CA_PROFILES:
    raise ImproperlyConfigured(f"{CA_DEFAULT_PROFILE}: CA_DEFAULT_PROFILE is not defined as a profile.")

# Load and process CA_PASSWORDS
CA_PASSWORDS: dict[str, bytes] = getattr(settings, "CA_PASSWORDS", {})
for _ca_passwords_key, _ca_passwords_value in CA_PASSWORDS.items():
    if isinstance(_ca_passwords_value, str):
        CA_PASSWORDS[_ca_passwords_key] = _ca_passwords_value.encode("utf-8")
    elif not isinstance(_ca_passwords_value, bytes):
        raise ImproperlyConfigured(f"CA_PASSWORDS: {_ca_passwords_value}: value must be bytes or str.")
CA_PASSWORDS = {key.upper().replace(":", ""): value for key, value in CA_PASSWORDS.items()}

CA_DEFAULT_SIGNATURE_HASH_ALGORITHM = _get_hash_algorithm("CA_DEFAULT_SIGNATURE_HASH_ALGORITHM", "SHA-512")
CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM = _get_hash_algorithm(
    "CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM", "SHA-256"
)

CA_DEFAULT_EXPIRES: timedelta = getattr(settings, "CA_DEFAULT_EXPIRES", timedelta(days=730))
if isinstance(CA_DEFAULT_EXPIRES, int):
    CA_DEFAULT_EXPIRES = timedelta(days=CA_DEFAULT_EXPIRES)
elif not isinstance(CA_DEFAULT_EXPIRES, timedelta):
    raise ImproperlyConfigured(f"CA_DEFAULT_EXPIRES: {CA_DEFAULT_EXPIRES}: Must be int or timedelta")
if CA_DEFAULT_EXPIRES <= timedelta():
    raise ImproperlyConfigured(f"CA_DEFAULT_EXPIRES: {CA_DEFAULT_EXPIRES}: Must have positive value")

CA_DEFAULT_KEY_BACKEND: str = getattr(settings, "CA_DEFAULT_KEY_BACKEND", "default")
CA_DEFAULT_STORAGE_ALIAS: str = getattr(settings, "CA_DEFAULT_STORAGE_ALIAS", "django-ca")
CA_KEY_BACKENDS: dict[str, dict[str, Any]] = getattr(
    settings,
    "CA_KEY_BACKENDS",
    {
        CA_DEFAULT_KEY_BACKEND: {
            "BACKEND": constants.DEFAULT_STORAGE_BACKEND,
            "OPTIONS": {"storage_alias": CA_DEFAULT_STORAGE_ALIAS},
        }
    },
)

# Old file storage settings
# pragma: only django-ca<2.0: CA_FILE_* settings can be removed in django-ca==2.0
CA_FILE_STORAGE = getattr(settings, "CA_FILE_STORAGE", global_settings.DEFAULT_FILE_STORAGE)
CA_FILE_STORAGE_KWARGS = getattr(
    settings,
    "CA_FILE_STORAGE_KWARGS",
    {
        "location": getattr(settings, "CA_DIR", os.path.join(settings.BASE_DIR, "files")),
        "file_permissions_mode": 0o600,
        "directory_permissions_mode": 0o700,
    },
)

# Decide if we should use Celery or not
CA_USE_CELERY = getattr(settings, "CA_USE_CELERY", None)
if CA_USE_CELERY is None:
    try:
        from celery import shared_task

        CA_USE_CELERY = True
    except ImportError:
        CA_USE_CELERY = False
elif CA_USE_CELERY is True:
    try:
        from celery import shared_task  # noqa: F401
    except ImportError as ex:
        raise ImproperlyConfigured("CA_USE_CELERY set to True, but Celery is not installed") from ex
