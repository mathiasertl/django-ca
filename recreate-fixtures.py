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

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime
from datetime import timedelta
from unittest.mock import patch

from six.moves import reload_module

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID

try:
    from freezegun import freeze_time
except ImportError:

    @contextmanager
    def freeze_time(value):
        yield


_rootdir = os.path.dirname(os.path.realpath(__file__))  # NOQA: E402
_sphinx_dir = os.path.join(_rootdir, "docs", "source", "_files")  # NOQA: E402
sys.path.insert(0, os.path.join(_rootdir, "ca"))  # NOQA: E402
os.environ["DJANGO_SETTINGS_MODULE"] = "ca.test_settings"  # NOQA: E402
# pylint: disable=wrong-import-position
import django  # NOQA: E402 isort:skip

django.setup()  # NOQA: E402

from django.conf import settings  # NOQA: E402
from django.core.management import call_command as manage  # NOQA: E402
from django.test.utils import override_settings  # NOQA: E402
from django.urls import reverse  # NOQA: E402

from django_ca import ca_settings  # NOQA: E402
from django_ca.extensions import OID_TO_EXTENSION  # NOQA: E402
from django_ca.extensions import Extension  # NOQA: E402
from django_ca.extensions.utils import PolicyInformation  # NOQA: E402
from django_ca.models import Certificate  # NOQA: E402
from django_ca.models import CertificateAuthority  # NOQA: E402
from django_ca.profiles import profiles  # NOQA:  E402
from django_ca.subject import Subject  # NOQA: E402
from django_ca.utils import ca_storage  # NOQA: E402
from django_ca.utils import hex_to_bytes  # NOQA: E402

# pylint: enable=wrong-import-position

now = datetime.utcnow().replace(second=0, minute=0)

parser = argparse.ArgumentParser(description="Regenerate fixtures for testing.")
parser.add_argument(
    "--only-contrib", default=False, action="store_true", help="Only update data from contrib certificates."
)
parser.add_argument(
    "--no-delay",
    dest="delay",
    action="store_false",
    default=True,
    help="Do not delay validity into the future.",
)
parser.add_argument(
    "--no-ocsp", dest="ocsp", action="store_false", default=True, help="Do not generate OCSP requests."
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
    default=getattr(settings, "FIXTURES_DIR", ""),
    help="Where to store generated certificates (default: %(default)s).",
)
args = parser.parse_args()

manage("migrate", verbosity=0)

# Some variables used in various places throughout the code
out_path = os.path.join(args.dest, "cert-data.json")
_timeformat = "%Y-%m-%d %H:%M:%S"
key_size = 2048  # Size for private keys
ca_base_cn = "ca.example.com"
root_pathlen = None
child_pathlen = 0
ecc_pathlen = 1
pwd_pathlen = 2
dsa_pathlen = 3
dsa_algorithm = "SHA1"
testserver = "http://%s" % ca_settings.CA_DEFAULT_HOSTNAME

if not os.path.exists(args.dest):
    os.makedirs(args.dest)


class override_tmpcadir(override_settings):
    """Simplified copy of the same decorator in tests.base."""

    def enable(self):
        self.options["CA_DIR"] = tempfile.mkdtemp()
        self.mock = patch.object(ca_storage, "location", self.options["CA_DIR"])
        self.mock_ = patch.object(ca_storage, "_location", self.options["CA_DIR"])
        self.mock.start()
        self.mock_.start()

        super(override_tmpcadir, self).enable()

        self.mockc = patch.object(ca_settings, "CA_DIR", self.options["CA_DIR"])
        self.mockc.start()

    def disable(self):
        super(override_tmpcadir, self).disable()
        self.mock.stop()
        self.mock_.stop()
        self.mockc.stop()
        shutil.rmtree(self.options["CA_DIR"])
        reload_module(ca_settings)


def create_key(path):
    subprocess.check_call(["openssl", "genrsa", "-out", path, str(key_size)], stderr=subprocess.DEVNULL)


def create_csr(key_path, path, subject="/CN=ignored.example.com"):
    create_key(key_path)
    subprocess.check_call(
        ["openssl", "req", "-new", "-key", key_path, "-out", path, "-utf8", "-batch", "-subj", subject]
    )

    with open(path) as stream:
        csr = stream.read()
    return x509.load_pem_x509_csr(csr.encode("utf-8"), default_backend())


def update_cert_data(cert, data):
    data["serial"] = cert.serial
    data["hpkp"] = cert.hpkp_pin
    data["valid_from"] = cert.pub.loaded.not_valid_before.strftime(_timeformat)
    data["valid_until"] = cert.pub.loaded.not_valid_after.strftime(_timeformat)

    data["md5"] = cert.get_digest("MD5")
    data["sha1"] = cert.get_digest("SHA1")
    data["sha256"] = cert.get_digest("SHA256")
    data["sha512"] = cert.get_digest("SHA512")

    aki = cert.authority_key_identifier
    if aki is not None:
        data["authority_key_identifier"] = aki.serialize()

    basic_constraints = cert.basic_constraints
    if basic_constraints:
        data["basic_constraints"] = basic_constraints.serialize()

    ski = cert.subject_key_identifier
    if ski is not None:
        data["subject_key_identifier"] = ski.serialize()

    key_usage = cert.key_usage
    if key_usage is not None:
        data["key_usage"] = key_usage.serialize()

    aia = cert.authority_information_access
    if aia is not None:
        data["authority_information_access"] = aia.serialize()

    san = cert.subject_alternative_name
    if san is not None:
        data["subject_alternative_name"] = san.serialize()

    ian = cert.issuer_alternative_name
    if ian is not None:
        data["issuer_alternative_name"] = ian.serialize()

    eku = cert.extended_key_usage
    if eku is not None:
        data["extended_key_usage"] = eku.serialize()
    crldp = cert.crl_distribution_points
    if crldp is not None:
        data["crl_distribution_points"] = crldp.serialize()


def write_ca(cert, data, password=None):
    key_dest = os.path.join(args.dest, data["key_filename"])
    pub_dest = os.path.join(args.dest, data["pub_filename"])
    key_der_dest = os.path.join(args.dest, data["key_der_filename"])
    pub_der_dest = os.path.join(args.dest, data["pub_der_filename"])

    # write files to dest
    shutil.copy(ca_storage.path(cert.private_key_path), key_dest)
    with open(pub_dest, "w") as stream:
        stream.write(cert.pub.pem)

    if password is None:
        encryption = NoEncryption()
    else:
        encryption = BestAvailableEncryption(password)

    key_der = cert.key(password=password).private_bytes(
        encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption
    )
    with open(key_der_dest, "wb") as stream:
        stream.write(key_der)
    with open(pub_der_dest, "wb") as stream:
        stream.write(cert.pub.der)

    # These keys are only present in CAs:
    data["issuer_url"] = ca.issuer_url
    data["crl_url"] = ca.crl_url
    data["ca_crl_url"] = "%s%s" % (testserver, reverse("django_ca:ca-crl", kwargs={"serial": ca.serial}))
    data["ocsp_url"] = "%s%s" % (
        testserver,
        reverse("django_ca:ocsp-cert-post", kwargs={"serial": ca.serial}),
    )

    # Update common data for CAs and certs
    update_cert_data(cert, data)


def copy_cert(cert, data, key_path, csr_path):
    key_dest = os.path.join(args.dest, data["key_filename"])
    csr_dest = os.path.join(args.dest, data["csr_filename"])
    pub_dest = os.path.join(args.dest, data["pub_filename"])
    key_der_dest = os.path.join(args.dest, data["key_der_filename"])
    pub_der_dest = os.path.join(args.dest, data["pub_der_filename"])

    shutil.copy(key_path, key_dest)
    shutil.copy(csr_path, csr_dest)
    with open(pub_dest, "w") as stream:
        stream.write(cert.pub.pem)

    with open(key_dest, "rb") as stream:
        priv_key = stream.read()
    priv_key = load_pem_private_key(priv_key, None, default_backend())
    key_der = priv_key.private_bytes(
        encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )
    with open(key_der_dest, "wb") as stream:
        stream.write(key_der)
    with open(pub_der_dest, "wb") as stream:
        stream.write(cert.pub.der)

    data["crl"] = cert.ca.crl_url
    data["subject"] = cert.distinguished_name
    data["parsed_cert"] = cert

    update_cert_data(cert, data)


def update_contrib(data, cert, name, filename):
    cert_data = {
        "name": name,
        "cn": cert.cn,
        "cat": "sphinx-contrib",
        "pub_filename": filename,
        "key_filename": False,
        "csr_filename": False,
        "valid_from": parsed.not_valid_before.strftime(_timeformat),
        "valid_until": parsed.not_valid_after.strftime(_timeformat),
        "serial": cert.serial,
        "subject": cert.distinguished_name,
        "hpkp": cert.hpkp_pin,
        "md5": cert.get_digest("MD5"),
        "sha1": cert.get_digest("SHA1"),
        "sha256": cert.get_digest("SHA256"),
        "sha512": cert.get_digest("SHA512"),
    }

    for ext in cert.extensions:
        if isinstance(ext, Extension):
            key = OID_TO_EXTENSION[ext.oid].key
            cert_data[key] = ext.serialize()
        elif isinstance(ext, tuple):
            print("### get extension tuple!!!")
            key, value = ext
            if isinstance(value[1], x509.ObjectIdentifier):
                # Currently just some old StartSSL extensions for Netscape (!)
                continue
            else:
                cert_data[key] = value

    try:
        ext = cert.pub.loaded.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        cert_data["policy_texts"] = [PolicyInformation(p).as_text() for p in ext]
    except x509.ExtensionNotFound:
        pass

    data[name] = cert_data


data = {
    "root": {
        "type": "ca",
        "password": None,
        "pathlen": root_pathlen,
        "basic_constraints": {
            "critical": True,
            "value": {"ca": True},
        },
        "key_usage": "critical,cRLSign,keyCertSign",
    },
    "child": {
        "type": "ca",
        "delta": timedelta(days=3),
        "parent": "root",
        "password": None,
        "basic_constraints": {
            "critical": True,
            "value": {
                "ca": True,
                "pathlen": child_pathlen,
            },
        },
        "pathlen": child_pathlen,
        "max_pathlen": 0,
    },
    "ecc": {
        "type": "ca",
        "password": None,
        "basic_constraints": {
            "critical": True,
            "value": {
                "ca": True,
                "pathlen": ecc_pathlen,
            },
        },
        "pathlen": ecc_pathlen,
        "key_type": "ECC",
        "max_pathlen": 1,
    },
    "dsa": {
        "type": "ca",
        "algorithm": dsa_algorithm,
        "password": None,
        "basic_constraints": {
            "critical": True,
            "value": {
                "ca": True,
                "pathlen": dsa_pathlen,
            },
        },
        "pathlen": dsa_pathlen,
        "max_pathlen": 3,
    },
    "pwd": {
        "type": "ca",
        "password": b"testpassword",
        "basic_constraints": {
            "critical": True,
            "value": {
                "ca": True,
                "pathlen": pwd_pathlen,
            },
        },
        "pathlen": pwd_pathlen,
        "max_pathlen": 2,
    },
    "root-cert": {
        "ca": "root",
        "delta": timedelta(days=5),
        "pathlen": root_pathlen,
        "csr": True,
    },
    "child-cert": {
        "ca": "child",
        "delta": timedelta(days=5),
        "csr": True,
    },
    "ecc-cert": {
        "ca": "ecc",
        "delta": timedelta(days=5),
        "csr": True,
        "key_type": "ECC",
    },
    "pwd-cert": {
        "ca": "pwd",
        "delta": timedelta(days=5),
        "csr": True,
    },
    "dsa-cert": {
        "ca": "dsa",
        "delta": timedelta(days=5),
        "algorithm": dsa_algorithm,
        "csr": True,
    },
    "profile-client": {
        "ca": "child",
        "delta": timedelta(days=10),
        "csr": True,
    },
    "profile-server": {
        "ca": "child",
        "delta": timedelta(days=10),
        "csr": True,
    },
    "profile-webserver": {
        "ca": "child",
        "delta": timedelta(days=10),
        "csr": True,
    },
    "profile-enduser": {
        "ca": "child",
        "delta": timedelta(days=10),
        "csr": True,
    },
    "profile-ocsp": {
        "ca": "child",
        "delta": timedelta(days=10),
        "csr": True,
    },
    "no-extensions": {
        "ca": "child",
        "delta": timedelta(days=15),
        "csr": True,
    },
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
            "issuer_alternative_name": {
                "value": [
                    "http://ian.child.example.com/",
                ],
            },
            "tls_feature": {
                "critical": True,
                "value": ["OCSPMustStaple", "MultipleCertStatusRequest"],
            },
            "key_usage": {
                "value": ["encipherOnly", "keyAgreement", "nonRepudiation"],
            },
            "extended_key_usage": {
                "value": [
                    "serverAuth",
                    "clientAuth",
                    "codeSigning",
                    "emailProtection",
                ],
            },
            "subject_alternative_name": {
                "value": [
                    "san1.all-extensions.example.com",
                    "san2.all-extensions.example.com",
                ]
            },
            "ocsp_no_check": {
                "critical": False,
            },
            "precert_poison": {
                "critical": True,
            },
            "freshest_crl": {
                "value": [  # two distribution points
                    {
                        "full_name": ["URI:https://example.com"],
                    },
                ]
            },
            "inhibit_any_policy": {
                "value": 1,
            },
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
                "value": {
                    "ca": False,
                },
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
                        "crl_issuer": [
                            "http://crl.ca.example.com",
                            "http://crl.ca.example.net",
                        ],
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
                },
            },
            "tls_feature": {
                "critical": False,  # critical in all-extensions
                "value": ["OCSPMustStaple"],
            },
        },
    },
}
ocsp_data = {
    "nonce": {
        "name": "nonce",
        "filename": "nonce.req",
        "nonce": "04:0E:6C:C4:B6:CC:50:E8:D8:BD:16:78:41:20:0D:39",
        "asn1crypto_nonce": "6C:C4:B6:CC:50:E8:D8:BD:16:78:41:20:0D:39",
    },
    "no-nonce": {
        "name": "no-nonce",
        "filename": "no-nonce.req",
    },
}

# Autocompute some values (name, filenames, ...) based on the dict key
for cert, cert_values in data.items():
    cert_values["name"] = cert
    cert_values.setdefault("type", "cert")
    cert_values.setdefault("cat", "generated")
    cert_values.setdefault("algorithm", "SHA256")
    cert_values.setdefault("subject", {})
    cert_values["subject"].setdefault("CN", "%s.example.com" % cert_values["name"])
    cert_values["subject_str"] = str(Subject(cert_values["subject"]))
    cert_values["csr_subject"] = {
        k: "csr.%s" % v if k != "C" else v for k, v in cert_values["subject"].items()
    }
    cert_values["csr_subject_str"] = str(Subject(cert_values["csr_subject"]))
    cert_values["key_filename"] = "%s.key" % cert_values["name"]
    cert_values["pub_filename"] = "%s.pub" % cert_values["name"]
    cert_values["key_der_filename"] = "%s.key.der" % cert_values["name"]
    cert_values["pub_der_filename"] = "%s.pub.der" % cert_values["name"]
    cert_values.setdefault("key_size", key_size)
    cert_values.setdefault("key_type", "RSA")
    cert_values.setdefault("delta", timedelta())
    if cert_values.pop("csr", False):
        cert_values["csr_filename"] = "%s.csr" % cert_values["name"]
    else:
        cert_values["csr_filename"] = False

    if cert_values.get("type") == "ca":
        data[cert].setdefault("expires", timedelta(days=args.ca_validity))
    else:
        data[cert]["cn"] = "%s.example.com" % cert
        data[cert].setdefault("expires", timedelta(days=args.cert_validity))

ca_names = [v["name"] for k, v in data.items() if v.get("type") == "ca"]

# sort ca_names so that any children are created last
ca_names = sorted(ca_names, key=lambda n: data[n].get("parent", ""))
ca_instances = []

if not args.only_contrib:
    with override_tmpcadir():
        # Create CAs
        for name in ca_names:
            kwargs = {}

            # Get some data from the parent, if present
            parent = data[name].get("parent")
            if parent:
                kwargs["parent"] = CertificateAuthority.objects.get(name=parent)
                kwargs["ca_crl_url"] = [data[parent]["ca_crl_url"]]

                # also update data
                data[name]["crl"] = data[parent]["ca_crl_url"]

            freeze_now = now
            if args.delay:
                freeze_now += data[name]["delta"]

            with freeze_time(freeze_now):
                ca = CertificateAuthority.objects.init(
                    name=data[name]["name"],
                    password=data[name]["password"],
                    subject=Subject(data[name]["subject"]).name,
                    expires=datetime.utcnow() + data[name]["expires"],
                    key_type=data[name]["key_type"],
                    key_size=data[name]["key_size"],
                    algorithm=data[name]["algorithm"],
                    pathlen=data[name]["pathlen"],
                    **kwargs
                )

            # Same values can only be added here because they require data from the already created CA
            crl_path = reverse("django_ca:crl", kwargs={"serial": ca.serial})
            ca.crl_url = "%s%s" % (testserver, crl_path)
            ca.save()

            ca_instances.append(ca)
            write_ca(ca, data[name], password=data[name]["password"])

        # add parent/child relationships
        data["root"]["children"] = [
            [data["child"]["name"], data["child"]["serial"]],
        ]

        # let's create a standard certificate for every CA
        for ca in ca_instances:
            name = "%s-cert" % ca.name
            key_path = os.path.join(ca_settings.CA_DIR, "%s.key" % name)
            csr_path = os.path.join(ca_settings.CA_DIR, "%s.csr" % name)
            csr = create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

            freeze_now = now
            if args.delay:
                freeze_now += data[name]["delta"]

            pwd = data[data[name]["ca"]]["password"]
            subject = Subject("/CN=%s" % data[name]["cn"])
            with freeze_time(freeze_now):
                cert = Certificate.objects.create_cert(
                    ca=ca,
                    csr=csr,
                    profile=profiles["server"],
                    expires=data[name]["expires"],
                    algorithm=getattr(hashes, data[name]["algorithm"])(),
                    password=pwd,
                    subject=subject,
                )
            copy_cert(cert, data[name], key_path, csr_path)

        # create a cert for every profile
        for profile in ca_settings.CA_PROFILES:
            name = "profile-%s" % profile
            ca = CertificateAuthority.objects.get(name=data[name]["ca"])

            key_path = os.path.join(ca_settings.CA_DIR, "%s.key" % name)
            csr_path = os.path.join(ca_settings.CA_DIR, "%s.csr" % name)
            csr = create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

            freeze_now = now
            if args.delay:
                freeze_now += data[name]["delta"]

            pwd = data[ca.name]["password"]
            subject = Subject("/CN=%s" % data[name]["cn"])
            with freeze_time(freeze_now):
                cert = Certificate.objects.create_cert(
                    ca=ca,
                    csr=csr,
                    profile=profiles[profile],
                    algorithm=getattr(hashes, data[name]["algorithm"])(),
                    expires=data[name]["expires"],
                    password=pwd,
                    subject=subject,
                )

            data[name]["profile"] = profile
            copy_cert(cert, data[name], key_path, csr_path)

        # create a cert with absolutely no extensions
        name = "no-extensions"
        ca = CertificateAuthority.objects.get(name=data[name]["ca"])
        key_path = os.path.join(ca_settings.CA_DIR, "%s.key" % name)
        csr_path = os.path.join(ca_settings.CA_DIR, "%s.csr" % name)
        csr = create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

        freeze_now = now
        if args.delay:
            freeze_now += data[name]["delta"]
        with freeze_time(freeze_now):
            no_ext_now = datetime.utcnow()
            pwd = data[ca.name]["password"]
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, data[name]["cn"])])

            builder = x509.CertificateBuilder()
            builder = builder.not_valid_before(no_ext_now)
            builder = builder.not_valid_after(no_ext_now + data[name]["expires"])
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.subject_name(subject)
            builder = builder.issuer_name(ca.pub.loaded.subject)
            builder = builder.public_key(csr.public_key())

            x509_cert = builder.sign(
                private_key=ca.key(pwd), algorithm=hashes.SHA256(), backend=default_backend()
            )
            cert = Certificate(ca=ca)
            cert.update_certificate(x509_cert)
            copy_cert(cert, data[name], key_path, csr_path)

        # create a cert with all extensions that we know
        # NOTE: This certificate is not really a meaningful certificate:
        #   * NameConstraints is only valid for CAs
        #   * KeyUsage and ExtendedKeyUsage are not meaningful
        # TODO: missing: unsupported extensions
        #   * Certificate Policies
        #   * Policy Constraints
        #   * Inhibit anyPolicy
        #   * Freshest CRL
        #   * PrecertificateSignedCertificateTimestamps (cannot be generated by cryptography 2.6:
        #       https://github.com/pyca/cryptography/issues/4531)
        #   * Policy Mappings (not supported by cryptography 2.6:
        #       https://github.com/pyca/cryptography/issues/1947)
        name = "all-extensions"
        ca = CertificateAuthority.objects.get(name=data[name]["ca"])
        pwd = data[ca.name]["password"]
        key_path = os.path.join(ca_settings.CA_DIR, "%s.key" % name)
        csr_path = os.path.join(ca_settings.CA_DIR, "%s.csr" % name)
        csr = create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

        with freeze_time(now + data[name]["delta"]):
            cert = Certificate.objects.create_cert(
                ca=ca,
                csr=csr,
                profile=profiles["webserver"],
                algorithm=getattr(hashes, data[name]["algorithm"])(),
                subject=data[name]["subject"],
                expires=data[name]["expires"],
                password=pwd,
                extensions=data[name]["extensions"],
            )
        data[name].update(data[name].pop("extensions"))  # cert_data expects this to be flat
        copy_cert(cert, data[name], key_path, csr_path)

        # Create a certificate with some alternative form of extension that might otherwise be untested:
        # * CRL with relative_name (full_name and relative_name are mutually exclusive!)
        name = "alt-extensions"
        ca = CertificateAuthority.objects.get(name=data[name]["ca"])
        ca.crl_url = ""
        pwd = data[ca.name]["password"]
        key_path = os.path.join(ca_settings.CA_DIR, "%s.key" % name)
        csr_path = os.path.join(ca_settings.CA_DIR, "%s.csr" % name)
        csr = create_csr(key_path, csr_path, subject=data[name]["csr_subject_str"])

        with freeze_time(now + data[name]["delta"]):
            cert = Certificate.objects.create_cert(
                ca=ca,
                csr=csr,
                profile=profiles["webserver"],
                algorithm=getattr(hashes, data[name]["algorithm"])(),
                subject=data[name]["subject"],
                expires=data[name]["expires"],
                password=pwd,
                extensions=data[name]["extensions"],
            )
        data[name].update(data[name].pop("extensions"))  # cert_data expects this to be flat
        copy_cert(cert, data[name], key_path, csr_path)

    # Rebuild example OCSP requests
    if args.ocsp:
        from cryptography.x509 import ocsp

        ocsp_base = os.path.join(args.dest, "ocsp")
        if not os.path.exists(ocsp_base):
            os.makedirs(ocsp_base)
        ocsp_builder = ocsp.OCSPRequestBuilder()
        ocsp_builder = ocsp_builder.add_certificate(
            data["child-cert"]["parsed_cert"].pub.loaded,
            CertificateAuthority.objects.get(name=data["child-cert"]["ca"]).pub.loaded,
            hashes.SHA1(),
        )

        no_nonce_req = ocsp_builder.build().public_bytes(Encoding.DER)
        with open(os.path.join(ocsp_base, ocsp_data["no-nonce"]["filename"]), "wb") as stream:
            stream.write(no_nonce_req)

        ocsp_builder = ocsp_builder.add_extension(
            x509.OCSPNonce(hex_to_bytes(ocsp_data["nonce"]["nonce"])), critical=False
        )
        nonce_req = ocsp_builder.build().public_bytes(Encoding.DER)
        with open(os.path.join(ocsp_base, ocsp_data["nonce"]["filename"]), "wb") as stream:
            stream.write(nonce_req)
else:
    # updating only contrib, so remove existing data
    data = {}

# Load data from Sphinx files
if args.generate_contrib:
    for filename in os.listdir(os.path.join(_sphinx_dir, "ca")):
        name, _ext = os.path.splitext(filename)

        with open(os.path.join(_sphinx_dir, "ca", filename), "rb") as stream:
            pem = stream.read()

        parsed = x509.load_pem_x509_certificate(pem, default_backend())
        ca = CertificateAuthority(name=name)
        ca.update_certificate(parsed)

        update_contrib(data, ca, name, filename)
        data[name]["type"] = "ca"
        data[name]["pathlen"] = ca.pathlen

    for filename in os.listdir(os.path.join(_sphinx_dir, "cert")):
        name, _ext = os.path.splitext(filename)

        contrib_ca = None
        if name in data:
            contrib_ca = name

        name = "%s-cert" % name

        with open(os.path.join(_sphinx_dir, "cert", filename), "rb") as stream:
            pem = stream.read()

        parsed = x509.load_pem_x509_certificate(pem, default_backend())
        cert = Certificate()
        cert.update_certificate(parsed)
        update_contrib(data, cert, name, filename)
        data[name]["type"] = "cert"

        if contrib_ca:
            data[name]["ca"] = contrib_ca


for name, cert_data in data.items():
    if "delta" in cert_data:
        del cert_data["delta"]
    if "expires" in cert_data:
        del cert_data["expires"]
    if "parsed_cert" in cert_data:
        del cert_data["parsed_cert"]

    if cert_data.get("password"):
        cert_data["password"] = cert_data["password"].decode("utf-8")

if args.only_contrib:
    with open(out_path, "r") as stream:
        fixture_data = json.load(stream)
    fixture_data["certs"].update(data)
else:
    fixture_data = {
        "timestamp": now.strftime(_timeformat),
        "certs": data,
        "ocsp": ocsp_data,
    }

with open(out_path, "w") as stream:
    json.dump(fixture_data, stream, indent=4)
