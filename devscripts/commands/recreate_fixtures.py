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

import ipaddress
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from devscripts import config
from devscripts.commands import DevCommand

DEFAULT_KEY_SIZE = 2048  # Size for private keys
TIMEFORMAT = "%Y-%m-%d %H:%M:%S"
ROOT_PATHLEN = None
CHILD_PATHLEN = 0
EC_PATHLEN = 1
PWD_PATHLEN = 2
DSA_PATHLEN = 3


def recreate_fixtures(  # pylint: disable=too-many-locals,too-many-statements
    dest, delay, only_contrib, regenerate_ocsp, generate_contrib, ca_validity, cert_validity
):
    """Main entry function to recreate fixtures."""
    # pylint: disable=import-outside-toplevel  # django needs to be set up
    from django.core.management import call_command as manage

    from devscripts.recreate_fixtures_helpers import (
        CertificateEncoder,
        _generate_contrib_files,
        create_cas,
        create_certs,
        create_special_certs,
        override_tmpcadir,
        regenerate_ocsp_files,
    )

    from django_ca.utils import format_name, sort_name, x509_name

    # pylint: enable=import-outside-toplevel
    # The time-offsets from now from which CAs/certs are valid starts 25 days in the past, with the largest
    # offset being 20 days. So the latest valid_from of any certs is five days in the past from when you run
    # this script.
    #
    # This is important in tests, as the "everything_valid" timestamp is 23 days after the date computed
    # below. If you use freezegun in a test and log in in the setUp method (before freezegun freezes time),
    # the session starts with the current, real time. Django ignores sessions that start in the future, so
    # tests that use the test client would fail if "everything_valid" is in the future.
    now = datetime.utcnow().replace(second=0, minute=0) - timedelta(days=25)

    manage("migrate", verbosity=0)

    out_path = dest / "cert-data.json"
    dest.mkdir(exist_ok=True)

    data = {
        "root": {
            "type": "ca",
            "pathlen": ROOT_PATHLEN,
            "basic_constraints": {"critical": True, "value": {"ca": True}},
            "key_usage": "critical,cRLSign,keyCertSign",
        },
        "child": {
            "type": "ca",
            "delta": timedelta(days=3),
            "parent": "root",
            "basic_constraints": {"critical": True, "value": {"ca": True, "pathlen": CHILD_PATHLEN}},
            "pathlen": CHILD_PATHLEN,
            "max_pathlen": 0,
        },
        "ec": {
            "type": "ca",
            "basic_constraints": {"critical": True, "value": {"ca": True, "pathlen": EC_PATHLEN}},
            "pathlen": EC_PATHLEN,
            "key_type": "EC",
            "max_pathlen": 1,
        },
        "dsa": {
            "type": "ca",
            "key_type": "DSA",
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
        "ed25519": {
            "type": "ca",
            "key_type": "Ed25519",
            "pathlen": 1,
            "max_pathlen": 1,
            "algorithm": None,
        },
        "ed448": {
            "type": "ca",
            "key_type": "Ed448",
            "pathlen": 1,
            "max_pathlen": 1,
            "algorithm": None,
        },
        "root-cert": {"ca": "root", "delta": timedelta(days=5), "pathlen": ROOT_PATHLEN, "csr": True},
        "child-cert": {"ca": "child", "delta": timedelta(days=5), "csr": True},
        "ec-cert": {"ca": "ec", "delta": timedelta(days=5), "csr": True, "key_type": "EC"},
        "pwd-cert": {"ca": "pwd", "delta": timedelta(days=5), "csr": True},
        "dsa-cert": {"ca": "dsa", "delta": timedelta(days=5), "csr": True, "key_type": "DSA"},
        "ed25519-cert": {
            "ca": "ed25519",
            "delta": timedelta(days=5),
            "csr": True,
            "algorithm": None,
            "key_type": "Ed25519",
        },
        "ed448-cert": {
            "ca": "ed448",
            "delta": timedelta(days=5),
            "csr": True,
            "algorithm": None,
            "key_type": "Ed448",
        },
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
                "extended_key_usage": x509.Extension(
                    oid=ExtensionOID.EXTENDED_KEY_USAGE,
                    critical=False,
                    value=x509.ExtendedKeyUsage(
                        [
                            ExtendedKeyUsageOID.CLIENT_AUTH,
                            ExtendedKeyUsageOID.CODE_SIGNING,
                            ExtendedKeyUsageOID.EMAIL_PROTECTION,
                            ExtendedKeyUsageOID.SERVER_AUTH,
                        ]
                    ),
                ),
                "freshest_crl": x509.Extension(
                    oid=ExtensionOID.FRESHEST_CRL,
                    critical=False,
                    value=x509.FreshestCRL(
                        [
                            x509.DistributionPoint(
                                full_name=[x509.UniformResourceIdentifier("https://example.com")],
                                relative_name=None,
                                crl_issuer=None,
                                reasons=None,
                            )
                        ]
                    ),
                ),
                "inhibit_any_policy": x509.Extension(
                    oid=ExtensionOID.INHIBIT_ANY_POLICY,
                    critical=True,  # required by RFC 5280
                    value=x509.InhibitAnyPolicy(skip_certs=1),
                ),
                "issuer_alternative_name": x509.Extension(
                    oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
                    critical=False,
                    value=x509.IssuerAlternativeName(
                        [x509.UniformResourceIdentifier("http://ian.child.example.com/")]
                    ),
                ),
                "key_usage": x509.Extension(
                    oid=ExtensionOID.KEY_USAGE,
                    critical=True,
                    value=x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=True,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=True,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=True,
                        decipher_only=False,
                    ),
                ),
                "name_constraints": x509.Extension(
                    oid=ExtensionOID.NAME_CONSTRAINTS,
                    critical=True,
                    value=x509.NameConstraints(
                        permitted_subtrees=[x509.DNSName(".org")],
                        excluded_subtrees=[x509.DNSName(".net")],
                    ),
                ),
                "policy_constraints": x509.Extension(
                    oid=ExtensionOID.POLICY_CONSTRAINTS,
                    critical=True,  # required by RFC 5280
                    value=x509.PolicyConstraints(require_explicit_policy=1, inhibit_policy_mapping=2),
                ),
                "precert_poison": x509.Extension(
                    oid=ExtensionOID.PRECERT_POISON, critical=True, value=x509.PrecertPoison()
                ),
                "ocsp_no_check": x509.Extension(
                    oid=ExtensionOID.OCSP_NO_CHECK, critical=False, value=x509.OCSPNoCheck()
                ),
                "subject_alternative_name": x509.Extension(
                    oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    critical=False,
                    value=x509.SubjectAlternativeName(
                        [
                            x509.DNSName("san1.all-extensions.example.com"),
                            x509.DNSName("san2.all-extensions.example.com"),
                        ]
                    ),
                ),
                "tls_feature": x509.Extension(
                    oid=ExtensionOID.TLS_FEATURE,
                    critical=True,
                    value=x509.TLSFeature(
                        [x509.TLSFeatureType.status_request_v2, x509.TLSFeatureType.status_request]
                    ),
                ),
            },
        },
        "alt-extensions": {
            "ca": "child",
            "delta": timedelta(days=20),
            "csr": True,
            "extensions": {
                "authority_key_identifier": x509.Extension(
                    oid=ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                    critical=True,  # not usually critical
                    value=x509.AuthorityKeyIdentifier(
                        key_identifier=b"0",
                        authority_cert_issuer=[x509.DNSName("example.com")],
                        authority_cert_serial_number=1,
                    ),
                ),
                "basic_constraints": x509.Extension(
                    oid=ExtensionOID.BASIC_CONSTRAINTS,
                    critical=False,  # usually critical,
                    value=x509.BasicConstraints(ca=False, path_length=None),
                ),
                "crl_distribution_points": x509.Extension(
                    oid=ExtensionOID.CRL_DISTRIBUTION_POINTS,
                    critical=True,  # not usually critical
                    value=x509.CRLDistributionPoints(
                        [
                            x509.DistributionPoint(
                                full_name=[x509.UniformResourceIdentifier("https://example.com")],
                                relative_name=None,
                                crl_issuer=None,
                                reasons=None,
                            ),
                            x509.DistributionPoint(
                                # values are otherwise not present in CRLs
                                full_name=None,
                                relative_name=x509.RelativeDistinguishedName(
                                    [x509.NameAttribute(NameOID.COMMON_NAME, "rdn.ca.example.com")]
                                ),
                                crl_issuer=[
                                    x509.UniformResourceIdentifier("http://crl.ca.example.com"),
                                    x509.UniformResourceIdentifier("http://crl.ca.example.net"),
                                ],
                                reasons=frozenset(
                                    [x509.ReasonFlags.key_compromise, x509.ReasonFlags.ca_compromise]
                                ),
                            ),
                        ]
                    ),
                ),
                "extended_key_usage": x509.Extension(
                    oid=ExtensionOID.EXTENDED_KEY_USAGE,
                    critical=True,  # not usually critical
                    value=x509.ExtendedKeyUsage(
                        [
                            ExtendedKeyUsageOID.CLIENT_AUTH,
                            ExtendedKeyUsageOID.CODE_SIGNING,
                            ExtendedKeyUsageOID.EMAIL_PROTECTION,
                            ExtendedKeyUsageOID.SERVER_AUTH,
                        ]
                    ),
                ),
                "issuer_alternative_name": x509.Extension(
                    oid=ExtensionOID.ISSUER_ALTERNATIVE_NAME,
                    critical=True,  # not usually critical
                    value=x509.IssuerAlternativeName(
                        [
                            x509.UniformResourceIdentifier("http://ian.example.com"),
                            x509.UniformResourceIdentifier("http://ian.example.net"),
                        ],
                    ),
                ),
                "key_usage": x509.Extension(
                    oid=ExtensionOID.KEY_USAGE,
                    critical=False,  # usually critical
                    value=x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=True,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=True,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=True,
                        decipher_only=False,
                    ),
                ),
                "name_constraints": x509.Extension(
                    oid=ExtensionOID.NAME_CONSTRAINTS,
                    critical=True,
                    value=x509.NameConstraints(
                        permitted_subtrees=[x509.DNSName(".org")], excluded_subtrees=None
                    ),
                ),
                "ocsp_no_check": x509.Extension(
                    oid=ExtensionOID.OCSP_NO_CHECK, critical=True, value=x509.OCSPNoCheck()
                ),
                "subject_alternative_name": x509.Extension(
                    oid=ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    critical=True,  # not usually critical
                    value=x509.SubjectAlternativeName(
                        [
                            x509.DNSName("san1.alt-extensions.example.com"),
                            x509.DNSName("san2.alt-extensions.example.com"),
                            x509.DNSName("san3.alt-extensions.example.com"),
                            x509.IPAddress(ipaddress.IPv4Address("192.0.2.3")),
                            x509.UniformResourceIdentifier("http://example.com"),
                        ]
                    ),
                ),
                "tls_feature": x509.Extension(
                    oid=ExtensionOID.TLS_FEATURE,
                    critical=False,  # critical in all-extensions
                    value=x509.TLSFeature([x509.TLSFeatureType.status_request]),
                ),
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
        cert_values["subject_str"] = format_name(sort_name(x509_name(cert_values["subject"].items())))
        cert_values["csr_subject"] = {
            k: f"csr.{v}" if k != "C" else v for k, v in cert_values["subject"].items()
        }
        cert_values["key_filename"] = f"{cert_name}.key"
        cert_values["pub_filename"] = f"{cert_name}.pub"
        cert_values["key_der_filename"] = f"{cert_name}.key.der"
        cert_values["pub_der_filename"] = f"{cert_name}.pub.der"
        cert_values.setdefault("key_type", "RSA")
        if cert_values["key_type"] in ("RSA", "DSA"):
            cert_values.setdefault("key_size", DEFAULT_KEY_SIZE)
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
            ca_instances = create_cas(dest, now, delay, data)
            create_certs(dest, ca_instances, now, delay, data)
            create_special_certs(dest, now, delay, data)

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
        json.dump(fixture_data, stream, indent=4, cls=CertificateEncoder, sort_keys=True)


class Command(DevCommand):
    """Regenerate fixtures for testing."""

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

    def handle(self, args):
        if "TOX_ENV_DIR" in os.environ:  # was invoked via tox
            # insert ca/ into path, otherwise it won't find test_settings in django project
            sys.path.insert(0, str(config.SRC_DIR))

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
        )
