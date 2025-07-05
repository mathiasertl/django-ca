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

"""Define various constants for tests. These are exported via django_ca.tests.base."""

import json
import os
import re
import shutil
import sys
import typing
from datetime import datetime, timedelta, timezone as tz
from importlib.metadata import version
from pathlib import Path
from typing import Any, cast

import packaging.version

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

import django

from django_ca.constants import EXTENSION_KEYS
from django_ca.tests.base.typehints import CsrDict, KeyDict, PubDict
from django_ca.utils import add_colons

try:
    import tomllib
except ImportError:  # pragma: only py<3.11
    import tomli as tomllib  # type: ignore[no-redef]


def _load_versions(versions: list[str]) -> tuple[tuple[int, int], ...]:
    return tuple(tuple(int(e) for e in v.split("."))[:2] for v in versions)  # type: ignore[misc]


_FILE_DIR = Path(__file__).resolve().parent  # dir of this file
TEST_DIR = _FILE_DIR.parent
FIXTURES_DIR = TEST_DIR / "fixtures"
BASE_DIR = TEST_DIR.parent.parent  # ca/
ROOT_DIR = BASE_DIR.parent  # git repository root

with open(ROOT_DIR / "pyproject.toml", "rb") as pyproject_stream:
    PROJECT_CONFIG = tomllib.load(pyproject_stream)

# Paths derived from ROOT_DIR
DOC_DIR = ROOT_DIR / "docs" / "source"
SPHINX_FIXTURES_DIR = DOC_DIR / "_files"

if os.environ.get("GITHUB_ACTION") and (geckodriver := shutil.which("geckodriver")):  # pragma: no cover
    GECKODRIVER_PATH = Path(geckodriver)
else:  # pragma: no cover
    GECKODRIVER_PATH = ROOT_DIR / "contrib" / "selenium" / "geckodriver"

if TOX_ENV_DIR := os.environ.get("TOX_ENV_DIR"):  # pragma: no cover
    GECKODRIVER_LOG_PATH = Path(TOX_ENV_DIR) / "geckodriver.log"
else:  # pragma: no cover
    GECKODRIVER_LOG_PATH = ROOT_DIR / "geckodriver.log"

RELEASE = PROJECT_CONFIG["django-ca"]["release"]
PYTHON_VERSIONS = _load_versions(RELEASE["python"])
CRYPTOGRAPHY_VERSIONS = cast(tuple[tuple[int], ...], _load_versions(RELEASE["cryptography"]))
DJANGO_VERSIONS = _load_versions(RELEASE["django"])
ACME_VERSIONS = _load_versions(RELEASE["acme"])
JOSEPY_VERSIONS = _load_versions(RELEASE["josepy"])
PYDANTIC_VERSIONS = _load_versions(RELEASE["pydantic"])

# Newest versions of software components.
NEWEST_PYTHON_VERSION = PYTHON_VERSIONS[-1]
NEWEST_CRYPTOGRAPHY_VERSION = CRYPTOGRAPHY_VERSIONS[-1]
NEWEST_DJANGO_VERSION = DJANGO_VERSIONS[-1]
NEWEST_ACME_VERSION = ACME_VERSIONS[-1]
NEWEST_PYDANTIC_VERSION = PYDANTIC_VERSIONS[-1]

# Determine if we're running on the respective newest versions
CRYPTOGRAPHY_VERSION = packaging.version.parse(cryptography.__version__).release
ACME_VERSION = packaging.version.parse(version("acme")).release
PYDANTIC_VERSION = packaging.version.parse(version("pydantic")).release
JOSEPY_VERSION = packaging.version.parse(version("josepy")).release

NEWEST_PYTHON = sys.version_info[0:2] == NEWEST_PYTHON_VERSION
NEWEST_CRYPTOGRAPHY = CRYPTOGRAPHY_VERSION[:1] == NEWEST_CRYPTOGRAPHY_VERSION
NEWEST_DJANGO = django.VERSION[:2] == NEWEST_DJANGO_VERSION
NEWEST_ACME = ACME_VERSION[:2] == NEWEST_ACME_VERSION
NEWEST_PYDANTIC = PYDANTIC_VERSION[:2] == NEWEST_PYDANTIC_VERSION
NEWEST_VERSIONS = NEWEST_PYTHON and NEWEST_CRYPTOGRAPHY and NEWEST_DJANGO and NEWEST_ACME and NEWEST_PYDANTIC

# Only run Selenium tests if we use the newest Python, cryptography and acme.
RUN_SELENIUM_TESTS = NEWEST_PYTHON and NEWEST_CRYPTOGRAPHY and NEWEST_ACME and NEWEST_PYDANTIC

# Fixture data used by test cases
with open(FIXTURES_DIR / "cert-data.json", encoding="utf-8") as cert_data_stream:
    FIXTURES_DATA = json.load(cert_data_stream)
CERT_DATA = FIXTURES_DATA["certs"]


# Update some data from contrib (data is not in cert-data.json, since we don't generate them)
CERT_DATA["multiple_ous"] = {
    "name": "multiple_ous",
    "subject": [
        ["C", "US"],
        ["O", "VeriSign, Inc."],
        ["OU", "Class 3 Public Primary Certification Authority - G2"],
        ["OU", "(c) 1998 VeriSign, Inc. - For authorized use only"],
        ["OU", "VeriSign Trust Network"],
    ],
    "cn": "",
    "key_filename": False,
    "csr_filename": False,
    "pub_filename": os.path.join("contrib", "multiple_ous.pub"),
    "key_type": "RSA",
    "cat": "contrib",
    "type": "cert",
    "not_before": "1998-05-18 00:00:00",
    "valid_until": "2028-08-01 23:59:59",
    "ca": "root",
    "serial": "7DD9FE07CFA81EB7107967FBA78934C6",
    "md5": "A2:33:9B:4C:74:78:73:D4:6C:E7:C1:F3:8D:CB:5C:E9",
    "sha1": "85:37:1C:A6:E5:50:14:3D:CE:28:03:47:1B:DE:3A:09:E8:F8:77:0F",
    "sha256": "83:CE:3C:12:29:68:8A:59:3D:48:5F:81:97:3C:0F:91:95:43:1E:DA:37:CC:5E:36:43:0E:79:C7:A8:88:63:8B",  # noqa: E501
    "sha512": "86:20:07:9F:8B:06:80:43:44:98:F6:7A:A4:22:DE:7E:2B:33:10:9B:65:72:79:C4:EB:F3:F3:0F:66:C8:6E:89:1D:4C:6C:09:1C:83:45:D1:25:6C:F8:65:EB:9A:B9:50:8F:26:A8:85:AE:3A:E4:8A:58:60:48:65:BB:44:B6:CE",  # NOQA
    "extensions": [],
}
CERT_DATA["cloudflare_1"] = {
    "name": "cloudflare_1",
    "subject": [
        ["OU", "Domain Control Validated"],
        ["OU", "PositiveSSL Multi-Domain"],
        ["CN", "sni24142.cloudflaressl.com"],
    ],
    "cn": "sni24142.cloudflaressl.com",
    "key_filename": False,
    "csr_filename": False,
    "pub_filename": os.path.join("contrib", "cloudflare_1.pub"),
    "cat": "contrib",
    "type": "cert",
    "key_type": "EC",
    "not_before": "2018-07-18 00:00:00",
    "valid_until": "2019-01-24 23:59:59",
    "ca": "root",
    "serial": "92529ABD85F0A6A4D6C53FD1C91011C1",
    "md5": "D6:76:03:E9:4F:3B:B0:F1:F7:E3:A1:40:80:8E:F0:4A",
    "sha1": "71:BD:B8:21:80:BD:86:E8:E5:F4:2B:6D:96:82:B2:EF:19:53:ED:D3",
    "sha256": "1D:8E:D5:41:E5:FF:19:70:6F:65:86:A9:A3:6F:DF:DE:F8:A0:07:22:92:71:9E:F1:CD:F8:28:37:39:02:E0:A1",  # NOQA
    "sha512": "FF:03:1B:8F:11:E8:A7:FF:91:4F:B9:97:E9:97:BC:77:37:C1:A7:69:86:F3:7C:E3:BB:BB:DF:A6:4F:0E:3C:C0:7F:B5:BC:CC:BD:0A:D5:EF:5F:94:55:E9:FF:48:41:34:B8:11:54:57:DD:90:85:41:2E:71:70:5E:FA:BA:E6:EA",  # NOQA
    "extensions": [
        {
            "type": "authority_key_identifier",
            "critical": False,
            "value": {"key_identifier": "QAlhZ/C8g3FP3hIILG/U1Ct2PZY="},
        },
        {
            "type": "subject_key_identifier",
            "critical": False,
            "value": "BYbYtO2pfiPuLud1qjssBggqk7I=",
        },
        {
            "type": "key_usage",
            "critical": True,
            "value": ["digital_signature"],
        },
        {
            "type": "basic_constraints",
            "critical": True,
            "value": {"ca": False, "path_length": None},
        },
        {
            "type": "extended_key_usage",
            "critical": False,
            "value": [
                ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
                ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
            ],
        },
        {
            "type": "certificate_policies",
            "value": [
                {
                    "policy_identifier": "1.3.6.1.4.1.6449.1.2.2.7",
                    "policy_qualifiers": ["https://secure.comodo.com/CPS"],
                },
                {"policy_identifier": "2.23.140.1.2.1"},
            ],
            "critical": False,
        },
        {
            "type": "crl_distribution_points",
            "value": [
                {
                    "full_name": [
                        {
                            "type": "URI",
                            "value": "http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl",
                        },
                    ],
                }
            ],
            "critical": False,
        },
        {
            "type": "authority_information_access",
            "critical": False,
            "value": [
                {
                    "access_method": AuthorityInformationAccessOID.CA_ISSUERS.dotted_string,
                    "access_location": {
                        "type": "URI",
                        "value": "http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt",
                    },
                },
                {
                    "access_method": AuthorityInformationAccessOID.OCSP.dotted_string,
                    "access_location": {
                        "type": "URI",
                        "value": "http://ocsp.comodoca4.com",
                    },
                },
            ],
        },
        {"type": "precert_poison", "critical": True},
        {
            "type": "subject_alternative_name",
            "value": [
                {"type": "DNS", "value": "sni24142.cloudflaressl.com"},
                {"type": "DNS", "value": "*.animereborn.com"},
                {"type": "DNS", "value": "*.beglideas.ga"},
                {"type": "DNS", "value": "*.chroma.ink"},
                {"type": "DNS", "value": "*.chuckscleanings.ga"},
                {"type": "DNS", "value": "*.clipvuigiaitris.ga"},
                {"type": "DNS", "value": "*.cmvsjns.ga"},
                {"type": "DNS", "value": "*.competegraphs.ga"},
                {"type": "DNS", "value": "*.consoleprints.ga"},
                {"type": "DNS", "value": "*.copybreezes.ga"},
                {"type": "DNS", "value": "*.corphreyeds.ga"},
                {"type": "DNS", "value": "*.cyanigees.ga"},
                {"type": "DNS", "value": "*.dadpbears.ga"},
                {"type": "DNS", "value": "*.dahuleworldwides.ga"},
                {"type": "DNS", "value": "*.dailyopeningss.ga"},
                {"type": "DNS", "value": "*.daleylexs.ga"},
                {"type": "DNS", "value": "*.danajweinkles.ga"},
                {"type": "DNS", "value": "*.dancewthyogas.ga"},
                {"type": "DNS", "value": "*.darkmoosevpss.ga"},
                {"type": "DNS", "value": "*.daurat.com.ar"},
                {"type": "DNS", "value": "*.deltaberg.com"},
                {"type": "DNS", "value": "*.drjahanobgyns.ga"},
                {"type": "DNS", "value": "*.drunkgirliess.ga"},
                {"type": "DNS", "value": "*.duhiepkys.ga"},
                {"type": "DNS", "value": "*.dujuanjsqs.ga"},
                {"type": "DNS", "value": "*.dumbiseasys.ga"},
                {"type": "DNS", "value": "*.dumpsoftdrinkss.ga"},
                {"type": "DNS", "value": "*.dunhavenwoodss.ga"},
                {"type": "DNS", "value": "*.durabiliteas.ga"},
                {"type": "DNS", "value": "*.duxmangroups.ga"},
                {"type": "DNS", "value": "*.dvpdrivewayss.ga"},
                {"type": "DNS", "value": "*.dwellwizes.ga"},
                {"type": "DNS", "value": "*.dwwkouis.ga"},
                {"type": "DNS", "value": "*.entertastic.com"},
                {"type": "DNS", "value": "*.estudiogolber.com.ar"},
                {"type": "DNS", "value": "*.letsretro.team"},
                {"type": "DNS", "value": "*.maccuish.org.uk"},
                {"type": "DNS", "value": "*.madamsquiggles.com"},
                {"type": "DNS", "value": "*.sftw.ninja"},
                {"type": "DNS", "value": "*.spangenberg.io"},
                {"type": "DNS", "value": "*.timmutton.com.au"},
                {"type": "DNS", "value": "*.wyomingsexbook.com"},
                {"type": "DNS", "value": "*.ych.bid"},
                {"type": "DNS", "value": "animereborn.com"},
                {"type": "DNS", "value": "beglideas.ga"},
                {"type": "DNS", "value": "chroma.ink"},
                {"type": "DNS", "value": "chuckscleanings.ga"},
                {"type": "DNS", "value": "clipvuigiaitris.ga"},
                {"type": "DNS", "value": "cmvsjns.ga"},
                {"type": "DNS", "value": "competegraphs.ga"},
                {"type": "DNS", "value": "consoleprints.ga"},
                {"type": "DNS", "value": "copybreezes.ga"},
                {"type": "DNS", "value": "corphreyeds.ga"},
                {"type": "DNS", "value": "cyanigees.ga"},
                {"type": "DNS", "value": "dadpbears.ga"},
                {"type": "DNS", "value": "dahuleworldwides.ga"},
                {"type": "DNS", "value": "dailyopeningss.ga"},
                {"type": "DNS", "value": "daleylexs.ga"},
                {"type": "DNS", "value": "danajweinkles.ga"},
                {"type": "DNS", "value": "dancewthyogas.ga"},
                {"type": "DNS", "value": "darkmoosevpss.ga"},
                {"type": "DNS", "value": "daurat.com.ar"},
                {"type": "DNS", "value": "deltaberg.com"},
                {"type": "DNS", "value": "drjahanobgyns.ga"},
                {"type": "DNS", "value": "drunkgirliess.ga"},
                {"type": "DNS", "value": "duhiepkys.ga"},
                {"type": "DNS", "value": "dujuanjsqs.ga"},
                {"type": "DNS", "value": "dumbiseasys.ga"},
                {"type": "DNS", "value": "dumpsoftdrinkss.ga"},
                {"type": "DNS", "value": "dunhavenwoodss.ga"},
                {"type": "DNS", "value": "durabiliteas.ga"},
                {"type": "DNS", "value": "duxmangroups.ga"},
                {"type": "DNS", "value": "dvpdrivewayss.ga"},
                {"type": "DNS", "value": "dwellwizes.ga"},
                {"type": "DNS", "value": "dwwkouis.ga"},
                {"type": "DNS", "value": "entertastic.com"},
                {"type": "DNS", "value": "estudiogolber.com.ar"},
                {"type": "DNS", "value": "letsretro.team"},
                {"type": "DNS", "value": "maccuish.org.uk"},
                {"type": "DNS", "value": "madamsquiggles.com"},
                {"type": "DNS", "value": "sftw.ninja"},
                {"type": "DNS", "value": "spangenberg.io"},
                {"type": "DNS", "value": "timmutton.com.au"},
                {"type": "DNS", "value": "wyomingsexbook.com"},
                {"type": "DNS", "value": "ych.bid"},
            ],
        },
    ],
}


def _load_key(data: dict[Any, Any]) -> KeyDict:
    with open(data["key_path"], "rb") as stream:
        raw = stream.read()

    parsed = serialization.load_der_private_key(
        raw, password=data.get("password"), unsafe_skip_rsa_key_validation=True
    )

    return {"parsed": typing.cast(CertificateIssuerPrivateKeyTypes, parsed)}


def _load_csr(data: dict[Any, Any]) -> CsrDict:
    with open(FIXTURES_DIR / data["csr_filename"], "rb") as stream:
        raw = stream.read()

    parsed = x509.load_der_x509_csr(raw)
    return {"parsed": parsed}


def _load_pub(data: dict[str, Any]) -> PubDict:
    with open(data["pub_path"], "rb") as stream:
        key_data = stream.read()

    if _cert_data["cat"] == "sphinx-contrib":
        parsed = x509.load_pem_x509_certificate(key_data)
        pem = key_data.decode("utf-8")
        der = parsed.public_bytes(Encoding.DER)
    else:
        der = key_data
        parsed = x509.load_der_x509_certificate(key_data)
        pem = parsed.public_bytes(Encoding.PEM).decode("utf-8")

    return {"pem": pem, "parsed": parsed, "der": der}


# Augment data with various pre-computed paths
for _name, _cert_data in CERT_DATA.items():
    if _cert_data["cat"] == "sphinx-contrib":
        basedir = SPHINX_FIXTURES_DIR / _cert_data["type"]
    else:
        basedir = FIXTURES_DIR

    if _key_filename := _cert_data.get("key_filename"):
        _cert_data["key_path"] = basedir / _cert_data["key_filename"]
    if _password := _cert_data.get("password"):
        _cert_data["password"] = _cert_data["password"].encode("utf-8")
    _cert_data["pub_path"] = basedir / _cert_data["pub_filename"]

    if _cert_data["type"] == "ca":
        _cert_data.setdefault("children", [])
        _cert_data["children"] = [(k, add_colons(v)) for k, v in _cert_data["children"]]

    # Load data from files
    if _cert_data.get("key_path"):
        _cert_data["key"] = _load_key(_cert_data)
    if _cert_data.get("csr_filename"):
        _cert_data["csr"] = _load_csr(_cert_data)
    _cert_data["pub"] = _load_pub(_cert_data)
    _cert: x509.Certificate = _cert_data["pub"]["parsed"]

    # Data derived from public key
    _cert_data["issuer"] = _cert.issuer
    _cert_data["serial_colons"] = add_colons(_cert_data["serial"])
    _not_before = _cert.not_valid_before_utc
    _not_after = _cert.not_valid_after_utc
    _cert_data["not_before"] = _not_before
    _cert_data["valid_until"] = _not_after
    _cert_data["not_before_str"] = _cert_data["not_before"].isoformat(" ")
    _cert_data["not_after_str"] = _cert_data["valid_until"].isoformat(" ")

    for extension in _cert.extensions:
        try:
            key = EXTENSION_KEYS[extension.oid]
        except KeyError:  # unknown extensions from StartSSL CA
            continue
        _cert_data[key] = extension

# Calculate some fixed timestamps that we reuse throughout the tests
TIMESTAMPS = {
    "base": datetime.fromisoformat(FIXTURES_DATA["timestamp"]),
    "before_everything": datetime(1990, 1, 1, tzinfo=tz.utc),
}
TIMESTAMPS["before_cas"] = TIMESTAMPS["base"] - timedelta(days=1)
TIMESTAMPS["before_child"] = TIMESTAMPS["base"] + timedelta(days=1)
TIMESTAMPS["after_child"] = TIMESTAMPS["base"] + timedelta(days=4)
TIMESTAMPS["ca_certs_valid"] = TIMESTAMPS["base"] + timedelta(days=7)
TIMESTAMPS["profile_certs_valid"] = TIMESTAMPS["base"] + timedelta(days=12)

# When creating fixtures, latest not_before of any generated cert is 20 days, we need to be after that
_root_cert: x509.Certificate = CERT_DATA["root-cert"]["pub"]["parsed"]
_time_base = _root_cert.not_valid_before_utc

TIMESTAMPS["everything_valid"] = TIMESTAMPS["base"] + timedelta(days=23)
TIMESTAMPS["everything_valid_naive"] = TIMESTAMPS["everything_valid"].astimezone(tz.utc).replace(tzinfo=None)
TIMESTAMPS["cas_expired"] = TIMESTAMPS["base"] + timedelta(days=731, seconds=3600)
TIMESTAMPS["ca_certs_expiring"] = CERT_DATA["root-cert"]["valid_until"] - timedelta(days=3)
TIMESTAMPS["ca_certs_expired"] = CERT_DATA["root-cert"]["valid_until"] + timedelta(seconds=3600)
TIMESTAMPS["profile_certs_expired"] = CERT_DATA["profile-server"]["valid_until"] + timedelta(seconds=3600)
TIMESTAMPS["everything_expired"] = TIMESTAMPS["base"] + timedelta(days=365 * 20)

# Regex used by certbot to split PEM-encoded certificate chains/bundles as of 2022-01-23. See also:
# 	https://github.com/certbot/certbot/blob/master/certbot/certbot/crypto_util.py
CERT_PEM_REGEX = re.compile(
    b"""-----BEGIN CERTIFICATE-----\r?
.+?\r?
-----END CERTIFICATE-----\r?
""",
    re.DOTALL,  # DOTALL (/s) because the base64text may include newlines
)
