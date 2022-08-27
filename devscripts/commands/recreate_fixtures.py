#!/usr/bin/env python3
#
# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

"""The recreate-fixtures sub-command recreates the entire test fixture data.

The test suite should be sufficiently modular to still run without errors after running this command."""

import json
import os
from datetime import datetime
from datetime import timedelta
from pathlib import Path

from cryptography.hazmat.primitives import hashes

from devscripts import config
from devscripts.commands import DevCommand

DEFAULT_KEY_SIZE = 2048  # Size for private keys
TIMEFORMAT = "%Y-%m-%d %H:%M:%S"
ROOT_PATHLEN = None
CHILD_PATHLEN = 0
ECC_PATHLEN = 1
PWD_PATHLEN = 2
DSA_PATHLEN = 3
DSA_ALGORITHM = hashes.SHA1()


def recreate_fixtures(  # pylint: disable=too-many-locals,too-many-statements
    dest, delay, only_contrib, regenerate_ocsp, generate_contrib, ca_validity, cert_validity, quiet=False
):
    """Main entry function to recreate fixtures."""
    # pylint: disable=import-outside-toplevel  # django needs to be set up
    from django.core.management import call_command as manage

    from devscripts.recreate_fixtures_helpers import CertificateEncoder
    from devscripts.recreate_fixtures_helpers import _generate_contrib_files
    from devscripts.recreate_fixtures_helpers import create_cas
    from devscripts.recreate_fixtures_helpers import create_certs
    from devscripts.recreate_fixtures_helpers import create_special_certs
    from devscripts.recreate_fixtures_helpers import override_tmpcadir
    from devscripts.recreate_fixtures_helpers import regenerate_ocsp_files

    from django_ca.subject import Subject

    # pylint: enable=import-outside-toplevel

    now = datetime.utcnow().replace(second=0, minute=0)

    manage("migrate", verbosity=0)

    out_path = dest / "cert-data.json"
    dest.mkdir(exist_ok=True)

    data = {
        "root": {
            "type": "ca",
            "password": None,
            "pathlen": ROOT_PATHLEN,
            "basic_constraints": {"critical": True, "value": {"ca": True}},
            "key_usage": "critical,cRLSign,keyCertSign",
        },
        "child": {
            "type": "ca",
            "delta": timedelta(days=3),
            "parent": "root",
            "password": None,
            "basic_constraints": {"critical": True, "value": {"ca": True, "pathlen": CHILD_PATHLEN}},
            "pathlen": CHILD_PATHLEN,
            "max_pathlen": 0,
        },
        "ecc": {
            "type": "ca",
            "password": None,
            "basic_constraints": {"critical": True, "value": {"ca": True, "pathlen": ECC_PATHLEN}},
            "pathlen": ECC_PATHLEN,
            "key_size": 256,  # Value is unused in key generation, but needed for validation
            "key_type": "ECC",
            "max_pathlen": 1,
        },
        "dsa": {
            "type": "ca",
            "algorithm": DSA_ALGORITHM,
            "password": None,
            "basic_constraints": {"critical": True, "value": {"ca": True, "pathlen": DSA_PATHLEN}},
            "pathlen": DSA_PATHLEN,
            "max_pathlen": 3,
        },
        "pwd": {
            "type": "ca",
            "password": b"testpassword",
            "basic_constraints": {"critical": True, "value": {"ca": True, "pathlen": PWD_PATHLEN}},
            "pathlen": PWD_PATHLEN,
            "max_pathlen": 2,
        },
        "root-cert": {"ca": "root", "delta": timedelta(days=5), "pathlen": ROOT_PATHLEN, "csr": True},
        "child-cert": {"ca": "child", "delta": timedelta(days=5), "csr": True},
        "ecc-cert": {"ca": "ecc", "delta": timedelta(days=5), "csr": True, "key_type": "ECC"},
        "pwd-cert": {"ca": "pwd", "delta": timedelta(days=5), "csr": True},
        "dsa-cert": {"ca": "dsa", "delta": timedelta(days=5), "algorithm": DSA_ALGORITHM, "csr": True},
        "profile-client": {"ca": "child", "delta": timedelta(days=10), "csr": True},
        "profile-server": {"ca": "child", "delta": timedelta(days=10), "csr": True},
        "profile-webserver": {"ca": "child", "delta": timedelta(days=10), "csr": True},
        "profile-enduser": {"ca": "child", "delta": timedelta(days=10), "csr": True},
        "profile-ocsp": {"ca": "child", "delta": timedelta(days=10), "csr": True},
        "no-extensions": {"ca": "child", "delta": timedelta(days=15), "csr": True},
        "all-extensions": {
            "ca": "child",
            "delta": timedelta(days=20),
            "csr": True,
            "subject": {
                "C": "AT",
                "ST": "Vienna",
                "L": "Vienna",
                "O": "Example",
                "OU": "Example OU",
                "CN": "all-extensions.example.com",
                "emailAddress": "user@example.com",
            },
            "extensions": {
                "name_constraints": {"value": {"permitted": ["DNS:.org"], "excluded": ["DNS:.net"]}},
                "issuer_alternative_name": {"value": ["http://ian.child.example.com/"]},
                "tls_feature": {"critical": True, "value": ["OCSPMustStaple", "MultipleCertStatusRequest"]},
                "key_usage": {"value": ["encipherOnly", "keyAgreement", "nonRepudiation"]},
                "extended_key_usage": {
                    "value": ["serverAuth", "clientAuth", "codeSigning", "emailProtection"],
                },
                "subject_alternative_name": {
                    "value": [
                        "san1.all-extensions.example.com",
                        "san2.all-extensions.example.com",
                    ]
                },
                "ocsp_no_check": {"critical": False},
                "precert_poison": {"critical": True},
                "freshest_crl": {"value": [{"full_name": ["URI:https://example.com"]}]},
                "inhibit_any_policy": {"value": 1},
                "policy_constraints": {
                    "value": {"require_explicit_policy": 1, "inhibit_policy_mapping": 2},
                },
            },
        },
        "alt-extensions": {
            "ca": "child",
            "delta": timedelta(days=20),
            "csr": True,
            "extensions": {
                "basic_constraints": {
                    "critical": False,  # usually critical
                    "value": {"ca": False},
                },
                "authority_key_identifier": {
                    "critical": True,  # not usually critical
                    "value": {
                        "key_identifier": b"0",
                        "authority_cert_issuer": ["example.com"],
                        "authority_cert_serial_number": 1,
                    },
                },
                "crl_distribution_points": {
                    "critical": True,  # not usually critical
                    "value": [  # two distribution points
                        {
                            "full_name": ["URI:https://example.com"],
                        },
                        {
                            # values are otherwise not present in CRLs
                            "relative_name": "/CN=rdn.ca.example.com",
                            "crl_issuer": ["http://crl.ca.example.com", "http://crl.ca.example.net"],
                            "reasons": ["key_compromise", "ca_compromise"],
                        },
                    ],
                },
                "extended_key_usage": {
                    "critical": True,  # not usually critical
                    "value": ["serverAuth", "clientAuth", "codeSigning", "emailProtection"],
                },
                "issuer_alternative_name": {
                    "critical": True,  # not usually critical
                    "value": [  # usually just one value
                        "http://ian.example.com",
                        "http://ian.example.net",
                    ],
                },
                "key_usage": {
                    "critical": False,  # usually critical
                    "value": ["encipherOnly", "keyAgreement", "nonRepudiation"],
                },
                "name_constraints": {
                    "critical": True,  # not usually critical
                    "value": {
                        "permitted": ["DNS:.org"],  # just permitted, no excluded
                    },
                },
                "ocsp_no_check": {
                    "critical": True,  # not usually critical
                },
                "subject_alternative_name": {
                    "critical": True,  # not usually critical
                    "value": {
                        "san1.alt-extensions.example.com",
                        "san2.alt-extensions.example.com",
                        "san3.alt-extensions.example.com",
                        "IP:192.0.2.3",
                        "URI:http://example.com",
                    },
                },
                "tls_feature": {
                    "critical": False,  # critical in all-extensions
                    "value": ["OCSPMustStaple"],
                },
            },
        },
    }

    # Autocompute some values (name, filenames, ...) based on the dict key
    for cert_name, cert_values in data.items():
        cert_values["name"] = cert_name
        cert_values.setdefault("type", "cert")
        cert_values.setdefault("cat", "generated")
        cert_values.setdefault("algorithm", hashes.SHA256())
        cert_values.setdefault("subject", {})
        cert_values["subject"].setdefault("CN", f"{cert_name}.example.com")
        cert_values["subject_str"] = str(Subject(cert_values["subject"]))
        cert_values["csr_subject"] = {
            k: f"csr.{v}" if k != "C" else v for k, v in cert_values["subject"].items()
        }
        cert_values["csr_subject_str"] = str(Subject(cert_values["csr_subject"]))
        cert_values["key_filename"] = f"{cert_name}.key"
        cert_values["pub_filename"] = f"{cert_name}.pub"
        cert_values["key_der_filename"] = f"{cert_name}.key.der"
        cert_values["pub_der_filename"] = f"{cert_name}.pub.der"
        cert_values.setdefault("key_size", DEFAULT_KEY_SIZE)
        cert_values.setdefault("key_type", "RSA")
        cert_values.setdefault("delta", timedelta())
        if cert_values.pop("csr", False):
            cert_values["csr_filename"] = f"{cert_name}.csr"
        else:
            cert_values["csr_filename"] = False

        if cert_values.get("type") == "ca":
            data[cert_name].setdefault("expires", timedelta(days=ca_validity))
        else:
            data[cert_name]["cn"] = f"{cert_name}.example.com"
            data[cert_name].setdefault("expires", timedelta(days=cert_validity))

    ocsp_data = {}
    if not only_contrib:
        with override_tmpcadir():
            ca_instances = create_cas(dest, now, delay, data, quiet=quiet)
            create_certs(dest, ca_instances, now, delay, data, quiet=quiet)
            create_special_certs(dest, now, delay, data, quiet=quiet)

        # Rebuild example OCSP requests
        if regenerate_ocsp:
            ocsp_data = regenerate_ocsp_files(dest, data)
    else:
        # updating only contrib, so remove existing data
        data = {}

    # Load data from Sphinx files
    if generate_contrib:
        _generate_contrib_files(data)

    for cert_values in data.values():
        if "delta" in cert_values:
            del cert_values["delta"]
        if "expires" in cert_values:
            del cert_values["expires"]
        if "parsed_cert" in cert_values:
            del cert_values["parsed_cert"]

        if cert_values.get("password"):
            cert_values["password"] = cert_values["password"].decode("utf-8")

    if only_contrib:
        with open(out_path, "r", encoding="utf-8") as stream:
            fixture_data = json.load(stream)
        fixture_data["certs"].update(data)
    else:
        fixture_data = {"timestamp": now.strftime(TIMEFORMAT), "certs": data, "ocsp": ocsp_data}

    with open(out_path, "w", encoding="utf-8") as stream:
        json.dump(fixture_data, stream, indent=4, cls=CertificateEncoder)


class Command(DevCommand):  # pylint: disable=missing-class-docstring
    help = "Regenerate fixtures for testing."

    def add_arguments(self, parser):
        parser.add_argument(
            "--only-contrib",
            default=False,
            action="store_true",
            help="Only update data from contrib certificates.",
        )
        parser.add_argument(
            "--no-delay",
            dest="delay",
            action="store_false",
            default=True,
            help="Do not delay validity into the future.",
        )
        parser.add_argument(
            "--no-ocsp",
            dest="ocsp",
            action="store_false",
            default=True,
            help="Do not generate OCSP requests.",
        )
        parser.add_argument(
            "--no-contrib",
            dest="generate_contrib",
            action="store_false",
            default=True,
            help="Do not update contrib data.",
        )
        parser.add_argument(
            "--ca-validity",
            metavar="DAYS",
            type=int,
            default=366,
            help="How long a CA should be valid (default: %(default)s)",
        )
        parser.add_argument(
            "--cert-validity",
            metavar="DAYS",
            type=int,
            default=183,
            help="How long a CERT should be valid (default: %(default)s).",
        )
        parser.add_argument(
            "--dest",
            default=config.FIXTURES_DIR,
            help="Where to store generated certificates (default: %(default)s).",
        )
        parser.add_argument("-q", "--quiet", action="store_true", default=False)

    def handle(self, args):
        os.environ["DJANGO_SETTINGS_MODULE"] = "ca.test_settings"
        self.setup_django()
        recreate_fixtures(
            dest=Path(args.dest),
            delay=args.delay,
            only_contrib=args.only_contrib,
            regenerate_ocsp=args.ocsp,
            generate_contrib=args.generate_contrib,
            ca_validity=args.ca_validity,
            cert_validity=args.cert_validity,
            quiet=args.quiet,
        )
