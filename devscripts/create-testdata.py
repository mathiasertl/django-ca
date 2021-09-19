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

"""Script that creates testdata that is used for integration and update tests.

.. WARNING::

    In order to easily copy this script into other environments, do not use any thirdparty modules besides
    django-ca and its dependencies.
"""

import argparse
import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import django
from django.contrib.auth import get_user_model
from django.db.utils import OperationalError

BASE_DIR = os.path.dirname(__file__)
CA_DIR = os.path.join(os.path.dirname(BASE_DIR), "ca")
DEFAULT_SETTINGS = "ca.settings"

parser = argparse.ArgumentParser(description="Create testdata for update and integration tests." "")
parser.add_argument("--settings", help=f"Value for DJANGO_SETTINGS_MODULE (default: {DEFAULT_SETTINGS}).")
parser.add_argument("--env", choices=["backend", "frontend"], help="The environment to run in.")
args = parser.parse_args()

if args.settings:
    os.environ["DJANGO_SETTINGS_MODULE"] = args.settings
else:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", DEFAULT_SETTINGS)

if os.path.exists(CA_DIR):
    sys.path.insert(0, CA_DIR)

try:
    django.setup()
except ModuleNotFoundError as ex:
    print(f"Error setting up Django: {ex}")
    sys.exit(1)

# pylint: disable=wrong-import-position # django_setup needs to be called first
from django_ca.models import Certificate  # NOQA: E402
from django_ca.models import CertificateAuthority  # NOQA: E402

# pylint: enable=wrong-import-position

User = get_user_model()


def test_initial_state(env):
    """Test the expected initial state of the database."""

    # Make sure that migrations where run
    try:
        CertificateAuthority.objects.all().exists()
    except OperationalError as ex:  # pylint: disable=redefined-outer-name
        print(f"Error accessing database: {ex}")
        print("HINT: Did you run migrations yet?")
        sys.exit(1)

    if env == "frontend":
        for name in ["rsa.example.com", "dsa.example.org", "ecc.example.net"]:
            if not CertificateAuthority.objects.filter(name=name).exists():
                print(f"Error: {name}: CA not found.")
                print("HINT: did you run in backend first?")

    else:
        if User.objects.all().exists():
            print("Error: Existing users found. This script is meant to run on an empty database.")
            sys.exit(1)
        if Certificate.objects.all().exists():
            print("Error: Existing data found. This script is meant to run on an empty database.")
            sys.exit(1)
        if CertificateAuthority.objects.all().exists():
            print("Error: Existing data found. This script is meant to run on an empty database.")
            sys.exit(1)


def create_cert(ca: CertificateAuthority, **kwargs) -> Certificate:
    """Shortcut to create a certificate."""
    common_name = f"cert.{ca.subject['CN']}"
    # NOTE: We don't care about the type of private key, as the CA only ever receives the CSR
    cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Create the most basic CSR
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
    csr_request = csr_builder.sign(cert_key, hashes.SHA256())

    # Create a certificate
    cert = Certificate.objects.create_cert(ca=ca, csr=csr_request, subject=f"/CN={common_name}", **kwargs)
    return cert


test_initial_state(args.env)

# admin user and root CAs are not created if "frontend" environment is selected
if args.env != "frontend":
    print("* User for admin interface: user / nopass")
    User.objects.create_superuser(username="user", password="nopass")

    rsa_root = CertificateAuthority.objects.init(name="rsa.example.com", subject="/CN=rsa.example.com")
    dsa_root = CertificateAuthority.objects.init(
        name="dsa.example.org",
        subject="/CN=dsa.example.org",
        key_type="DSA",
        algorithm=hashes.SHA1(),
    )
    ecc_root = CertificateAuthority.objects.init(
        name="ecc.example.net", subject="/CN=ecc.example.net", key_type="ECC"
    )

    rsa_child = CertificateAuthority.objects.init(
        name="child.rsa.example.com", subject="/CN=child.rsa.example.com", parent=rsa_root, path="ca/shared/"
    )
    dsa_child = CertificateAuthority.objects.init(
        name="child.dsa.example.org",
        subject="/CN=child.dsa.example.org",
        key_type="DSA",
        parent=dsa_root,
        algorithm=hashes.SHA1(),
        path="ca/shared/",
    )
    ecc_child = CertificateAuthority.objects.init(
        name="child.ecc.example.net",
        subject="/CN=child.ecc.example.net",
        key_type="ECC",
        parent=ecc_root,
        path="ca/shared/",
    )
else:
    rsa_root = CertificateAuthority.objects.get(name="rsa.example.com")
    dsa_root = CertificateAuthority.objects.get(name="dsa.example.org")
    ecc_root = CertificateAuthority.objects.get(name="ecc.example.net")
    rsa_child = CertificateAuthority.objects.get(name="child.rsa.example.com")
    dsa_child = CertificateAuthority.objects.get(name="child.dsa.example.org")
    ecc_child = CertificateAuthority.objects.get(name="child.ecc.example.net")

# we can only create certs for root CAs if we're not in the frontend environment
if args.env != "frontend":
    rsa_root_cert = create_cert(rsa_root)
    dsa_root_cert = create_cert(dsa_root, algorithm=hashes.SHA1())
    ecc_root_cert = create_cert(ecc_root)

if args.env != "backend":
    rsa_child_cert = create_cert(rsa_child)
    dsa_child_cert = create_cert(dsa_child, algorithm=hashes.SHA1())
    ecc_child_cert = create_cert(ecc_child)
