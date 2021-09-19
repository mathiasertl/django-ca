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

"""Script that validates testdata after an update.

.. WARNING::

    In order to easily copy this script into other environments, do not use any thirdparty modules besides
    django-ca and its dependencies.
"""

import argparse
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

import django

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

# pylint: disable=wrong-import-position # django_setup needs to be called first.
from django_ca.models import Certificate  # NOQA: E402
from django_ca.models import CertificateAuthority  # NOQA: E402

# pylint: enable=wrong-import-position

rsa_root = CertificateAuthority.objects.get(name="rsa.example.com")
dsa_root = CertificateAuthority.objects.get(name="dsa.example.org")
ecc_root = CertificateAuthority.objects.get(name="ecc.example.net")
rsa_child = CertificateAuthority.objects.get(name="child.rsa.example.com")
dsa_child = CertificateAuthority.objects.get(name="child.dsa.example.org")
ecc_child = CertificateAuthority.objects.get(name="child.ecc.example.net")

# List of CAs that are usable in the frontend
frontend_cas = ["child.rsa.example.com", "child.dsa.example.org", "child.ecc.example.net"]

for ca in CertificateAuthority.objects.all():
    if not ca.usable:
        print(f"{ca}: Not usable.")
        sys.exit(1)

    if args.env != "frontend" or (args.env == "frontend" and ca.name in frontend_cas):
        if not ca.key_exists:
            print(f"{ca}: Private key does not exist.")
            sys.exit(1)

        key = ca.key(password=None)

        # Verify the private key
        if ca.name.endswith("rsa.example.com"):
            if not isinstance(key, rsa.RSAPrivateKey):
                print(f"{ca}: Private key is not an RSA key.")
                sys.exit(1)
        elif ca.name.endswith("dsa.example.org"):
            if not isinstance(key, dsa.DSAPrivateKey):
                print(f"{ca}: Private key is not an RSA key.")
                sys.exit(1)
        elif ca.name.endswith("ecc.example.net"):
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                print(f"{ca}: Private key is not an RSA key.")
                sys.exit(1)
        else:
            print(f"{ca}: Cannot read private key.")
            sys.exit(1)

    # Verify that we can read the public key
    if not isinstance(ca.pub.loaded, x509.Certificate):
        print(f"{ca}: Cannot load certificate.")
        sys.exit(1)

for cert in Certificate.objects.all():
    if not isinstance(cert.csr.loaded, x509.CertificateSigningRequest):
        print(f"{cert}: Cannot load certificate.")
        sys.exit(1)
    if not isinstance(cert.pub.loaded, x509.Certificate):
        print(f"{cert}: Cannot load certificate.")
        sys.exit(1)

print("No errors reported.")
