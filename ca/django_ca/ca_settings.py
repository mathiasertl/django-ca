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
import re
import typing
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from django.conf import global_settings, settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

# IMPORTANT: Do **not** import anything but django_ca.constants/deprecation here, or you risk circular
# imports.
from django_ca import constants

if typing.TYPE_CHECKING:
    from django_ca.typehints import AllowedHashTypes


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

    name_attributes: List[x509.NameAttribute] = []
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


def _get_hash_algorithm(setting: str, default: str) -> "AllowedHashTypes":
    raw_value = getattr(settings, setting, default)
    try:
        return constants.HASH_ALGORITHM_TYPES[raw_value]()
    except KeyError as ex2:
        raise ImproperlyConfigured(f"{setting}: {raw_value}: Unknown hash algorithm.") from ex2


if "CA_DIR" in os.environ:  # pragma: no cover
    CA_DIR = os.path.join(os.environ["CA_DIR"], "files")
else:
    CA_DIR = getattr(settings, "CA_DIR", os.path.join(settings.BASE_DIR, "files"))

CA_DEFAULT_KEY_SIZE: int = getattr(settings, "CA_DEFAULT_KEY_SIZE", 4096)

CA_PROFILES: Dict[str, Dict[str, Any]] = {
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
        "cn_in_san": False,
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
        "cn_in_san": False,  # CAs frequently use human-readable name as CN
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

_CA_CRL_PROFILES: Dict[str, Dict[str, Any]] = {
    "user": {
        "expires": 86400,
        "scope": "user",
        "encodings": ["PEM", "DER"],
    },
    "ca": {
        "expires": 86400,
        "scope": "ca",
        "encodings": ["PEM", "DER"],
    },
}

# Get and sanitize default CA serial
# NOTE: This effectively duplicates utils.sanitize_serial()
CA_DEFAULT_CA = getattr(settings, "CA_DEFAULT_CA", "").replace(":", "").upper()
if CA_DEFAULT_CA != "0":
    CA_DEFAULT_CA = CA_DEFAULT_CA.lstrip("0")
if re.search("[^0-9A-F]", CA_DEFAULT_CA):
    raise ImproperlyConfigured(f"CA_DEFAULT_CA: {CA_DEFAULT_CA}: Serial contains invalid characters.")

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
CA_DEFAULT_NAME_ORDER: Tuple[x509.ObjectIdentifier, ...] = getattr(
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
    profile.setdefault("cn_in_san", True)

    if subject := profile.get("subject"):
        profile["subject"] = _normalize_x509_name(subject, f"subject in {profile_name} profile.")

if CA_DEFAULT_PROFILE not in CA_PROFILES:
    raise ImproperlyConfigured(f"{CA_DEFAULT_PROFILE}: CA_DEFAULT_PROFILE is not defined as a profile.")

CA_DEFAULT_ENCODING: Encoding = getattr(settings, "CA_DEFAULT_ENCODING", Encoding.PEM)
CA_NOTIFICATION_DAYS = getattr(settings, "CA_NOTIFICATION_DAYS", [14, 7, 3, 1])
CA_CRL_PROFILES: Dict[str, Dict[str, Any]] = getattr(settings, "CA_CRL_PROFILES", _CA_CRL_PROFILES)
CA_PASSWORDS: Dict[str, str] = getattr(settings, "CA_PASSWORDS", {})

# ACME settings
CA_ENABLE_ACME = getattr(settings, "CA_ENABLE_ACME", True)
ACME_ORDER_VALIDITY: timedelta = getattr(settings, "CA_ACME_ORDER_VALIDITY", timedelta(hours=1))
ACME_ACCOUNT_REQUIRES_CONTACT = getattr(settings, "CA_ACME_ACCOUNT_REQUIRES_CONTACT", True)
ACME_MAX_CERT_VALIDITY = getattr(settings, "CA_ACME_MAX_CERT_VALIDITY", timedelta(days=90))
ACME_DEFAULT_CERT_VALIDITY = getattr(settings, "CA_ACME_DEFAULT_CERT_VALIDITY", timedelta(days=90))

CA_MIN_KEY_SIZE = getattr(settings, "CA_MIN_KEY_SIZE", 2048)

CA_DEFAULT_HOSTNAME: Optional[str] = getattr(settings, "CA_DEFAULT_HOSTNAME", None)

CA_DEFAULT_SIGNATURE_HASH_ALGORITHM = _get_hash_algorithm("CA_DEFAULT_SIGNATURE_HASH_ALGORITHM", "SHA-512")
CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM = _get_hash_algorithm(
    "CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM", "SHA-256"
)

CA_DEFAULT_EXPIRES: timedelta = getattr(settings, "CA_DEFAULT_EXPIRES", timedelta(days=730))
if isinstance(CA_DEFAULT_EXPIRES, int):
    CA_DEFAULT_EXPIRES = timedelta(days=CA_DEFAULT_EXPIRES)
elif not isinstance(CA_DEFAULT_EXPIRES, timedelta):
    raise ImproperlyConfigured(f"CA_DEFAULT_EXPIRES: {CA_DEFAULT_EXPIRES}: Must be int or timedelta")
if isinstance(ACME_MAX_CERT_VALIDITY, int):
    ACME_MAX_CERT_VALIDITY = timedelta(days=ACME_MAX_CERT_VALIDITY)
if isinstance(ACME_DEFAULT_CERT_VALIDITY, int):
    ACME_DEFAULT_CERT_VALIDITY = timedelta(days=ACME_DEFAULT_CERT_VALIDITY)
if isinstance(ACME_ORDER_VALIDITY, int):
    ACME_ORDER_VALIDITY = timedelta(days=ACME_ORDER_VALIDITY)
if CA_DEFAULT_EXPIRES <= timedelta():
    raise ImproperlyConfigured(f"CA_DEFAULT_EXPIRES: {CA_DEFAULT_EXPIRES}: Must have positive value")

if CA_MIN_KEY_SIZE > CA_DEFAULT_KEY_SIZE:
    raise ImproperlyConfigured(f"CA_DEFAULT_KEY_SIZE cannot be lower then {CA_MIN_KEY_SIZE}")


# CA_DEFAULT_ECC_CURVE can be removed in django-ca==1.25.0
_CA_DEFAULT_ELLIPTIC_CURVE = getattr(settings, "CA_DEFAULT_ELLIPTIC_CURVE", ec.SECP256R1.name)
try:
    CA_DEFAULT_ELLIPTIC_CURVE = constants.ELLIPTIC_CURVE_TYPES[_CA_DEFAULT_ELLIPTIC_CURVE]
except KeyError as ex:
    raise ImproperlyConfigured(f"{_CA_DEFAULT_ELLIPTIC_CURVE}: Unknown CA_DEFAULT_ELLIPTIC_CURVE.") from ex

CA_FILE_STORAGE = getattr(settings, "CA_FILE_STORAGE", global_settings.DEFAULT_FILE_STORAGE)
CA_FILE_STORAGE_KWARGS = getattr(
    settings,
    "CA_FILE_STORAGE_KWARGS",
    {
        "location": CA_DIR,
        "file_permissions_mode": 0o600,
        "directory_permissions_mode": 0o700,
    },
)

CA_ENABLE_REST_API: bool = getattr(settings, "CA_ENABLE_REST_API", False)

# CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL was added in 1.26.0
CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL: Union[timedelta] = getattr(
    settings, "CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL", timedelta(days=1)
)
if isinstance(CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL, int):
    CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL = timedelta(seconds=CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL)
elif not isinstance(CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL, timedelta):
    raise ImproperlyConfigured("CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL must be a timedelta or int.")

CA_FILE_STORAGE_URL = "https://django-ca.readthedocs.io/en/latest/update.html#update-to-1-12-0-or-later"

# Decide if we should use Celery or not
CA_USE_CELERY = getattr(settings, "CA_USE_CELERY", None)
if CA_USE_CELERY is None:
    try:
        from celery import shared_task  # pylint: disable=unused-import

        CA_USE_CELERY = True
    except ImportError:
        CA_USE_CELERY = False
elif CA_USE_CELERY is True:
    try:
        from celery import shared_task  # NOQA: F401
    except ImportError:
        # pylint: disable=raise-missing-from; not really useful in this context
        raise ImproperlyConfigured("CA_USE_CELERY set to True, but Celery is not installed")
