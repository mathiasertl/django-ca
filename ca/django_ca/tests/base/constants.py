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
import sys
from importlib.metadata import version
from pathlib import Path
from typing import List, Tuple

import packaging.version

import cryptography

import django

# PYLINT NOTE: lazy import so that just importing this module has no external dependencies
try:
    import tomllib  # pylint: disable=import-outside-toplevel
except ImportError:  # pragma: only py<3.11
    # pylint: disable-next=import-outside-toplevel
    import tomli as tomllib  # type: ignore[no-redef]


def _load_latest_version(versions: List[str]) -> Tuple[int, int]:
    return sorted([tuple(int(e) for e in v.split("."))[:2] for v in versions])[
        -1
    ]  # type: ignore[return-value]


_FILE_DIR = Path(__file__).resolve().parent  # dir of this file
TEST_DIR = _FILE_DIR.parent
FIXTURES_DIR = TEST_DIR / "fixtures"
BASE_DIR = TEST_DIR.parent.parent  # ca/
ROOT_DIR = BASE_DIR.parent  # git repository root

with open(ROOT_DIR / "pyproject.toml", "rb") as stream:
    PROJECT_CONFIG = tomllib.load(stream)

# Paths derived from ROOT_DIR
DOC_DIR = ROOT_DIR / "docs" / "source"
GECKODRIVER_PATH = ROOT_DIR / "contrib" / "selenium" / "geckodriver"

if TOX_ENV_DIR := os.environ.get("TOX_ENV_DIR"):  # pragma: no cover
    GECKODRIVER_LOG_PATH = Path("TOX_ENV_DIR") / "geckodriver.log"
else:  # pragma: no cover
    GECKODRIVER_LOG_PATH = ROOT_DIR / "geckodriver.log"


# Newest versions of software components.
NEWEST_PYTHON_VERSION = _load_latest_version(PROJECT_CONFIG["django-ca"]["release"]["python"])
NEWEST_CRYPTOGRAPHY_VERSION = _load_latest_version(PROJECT_CONFIG["django-ca"]["release"]["cryptography"])
NEWEST_DJANGO_VERSION = _load_latest_version(PROJECT_CONFIG["django-ca"]["release"]["django"])
NEWEST_ACME_VERSION = _load_latest_version(PROJECT_CONFIG["django-ca"]["release"]["acme"])

# Determine if we're running on the respective newest versions
_parsed_cg_version = packaging.version.parse(cryptography.__version__).release
CRYPTOGRAPHY_VERSION = _parsed_cg_version[:2]
ACME_VERSION = packaging.version.parse(version("acme")).release

NEWEST_PYTHON = sys.version_info[0:2] == NEWEST_PYTHON_VERSION
NEWEST_CRYPTOGRAPHY = CRYPTOGRAPHY_VERSION == NEWEST_CRYPTOGRAPHY_VERSION
NEWEST_DJANGO = django.VERSION[:2] == NEWEST_DJANGO_VERSION
NEWEST_ACME = ACME_VERSION == NEWEST_ACME_VERSION
NEWEST_VERSIONS = NEWEST_PYTHON and NEWEST_CRYPTOGRAPHY and NEWEST_DJANGO and NEWEST_ACME

# Only run Selenium tests if we use the newest Python, cryptography and acme.
RUN_SELENIUM_TESTS = NEWEST_PYTHON and NEWEST_CRYPTOGRAPHY and NEWEST_ACME


# Fixture data used by test cases
with open(FIXTURES_DIR / "cert-data.json", encoding="utf-8") as cert_data_stream:
    FIXTURES_DATA = json.load(cert_data_stream)
CERT_DATA = FIXTURES_DATA["certs"]

for _name, _cert_data in CERT_DATA.items():
    if _key_filename := _cert_data.get("key_filename"):
        CERT_DATA[_name]["key_path"] = FIXTURES_DIR / _cert_data["key_filename"]
    if _key_der_filename := _cert_data.get("key_der_filename"):
        CERT_DATA[_name]["key_der_path"] = FIXTURES_DIR / _cert_data["key_der_filename"]
    if _pub_der_filename := _cert_data.get("pub_der_filename"):
        CERT_DATA[_name]["pub_der_path"] = FIXTURES_DIR / _cert_data["pub_der_filename"]
    if _password := _cert_data.get("password"):
        CERT_DATA[_name]["password"] = _cert_data["password"].encode("utf-8")
    CERT_DATA[_name]["pub_path"] = FIXTURES_DIR / _cert_data["pub_filename"]
    CERT_DATA[_name]["pub_path"] = FIXTURES_DIR / _cert_data["pub_filename"]
