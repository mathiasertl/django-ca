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

"""The init-demo subcommand generates useful demo data."""

import json
import os
import subprocess
import sys

from termcolor import colored

from cryptography import x509

from devscripts import config
from devscripts.commands import DevCommand
from devscripts.out import bold


def ok(msg=" OK.", **kwargs):  # pylint: disable=invalid-name
    """Just print "OK" in green."""
    print(colored(msg, "green"), **kwargs)


class Command(DevCommand):
    """Initialize this project with useful example data."""

    def add_arguments(self, parser):
        parser.add_argument(
            "--base-url", metavar="URL", default="http://localhost:8000/", help="Base URL for CRL/OCSP URLs."
        )

    def output_info(self, ca_dir, ca_storage, loaded_cas, certs, base_url):
        """Output demo info to the user."""
        from django.urls import reverse  # pylint: disable=import-outside-toplevel  # see handle() imports

        base_url = base_url.rstrip("/")
        cwd = os.getcwd()
        root = os.path.relpath(ca_storage.path(certs["root"]["pub_filename"]), cwd)
        child = os.path.relpath(ca_storage.path(certs["child"]["pub_filename"]), cwd)

        root_cert = os.path.relpath(ca_storage.path(certs["root-cert"]["pub_filename"]), cwd)
        child_cert = os.path.relpath(ca_storage.path(certs["child-cert"]["pub_filename"]), cwd)
        root_serial = loaded_cas["root"].serial[:11]
        child_serial = loaded_cas["child"].serial[:11]

        ocsp_post_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": certs["child"]["serial"]})
        ocsp_url = f"{base_url}{ocsp_post_path}"

        dump_crl = "python ca/manage.py dump_crl"

        print("")
        print(f"* All certificates are in {bold(ca_dir)}")
        ok("* Start webserver with the admin interface:")
        print(f'  * Run "{bold("python ca/manage.py runserver")}"')
        print(f"  * Visit {bold(f'{base_url}/admin/')}")
        print(f"  * User/Password: {bold('user')} / {bold('nopass')}")
        ok("* Create CRLs with:")
        print(f"  * {bold(f'{dump_crl} -f PEM --ca {root_serial} > root.crl')}")
        print(f"  * {bold(f'{dump_crl} -f PEM --ca {child_serial} > child.crl')}")
        ok("* Verify with CRL:")
        print(f"  * {bold(f'openssl verify -CAfile {root} -CRLfile root.crl -crl_check {root_cert}')}")
        print(f"  * {bold(f'openssl verify -CAfile {root} -crl_download -crl_check {root_cert}')}")
        ok("* Verify certificate with OCSP:")
        cmd = f"openssl ocsp -CAfile {root} -issuer {child} -cert {child_cert} -url {ocsp_url} -resp_text"
        print(f"    {bold(cmd)}")

    def save_fixture_data(self, ca_settings, fixture_data):
        """Save loaded fixture data to database."""
        # pylint: disable=import-outside-toplevel  # see handle() imports
        from django.contrib.auth import get_user_model

        from django_ca.models import Certificate
        from django_ca.models import CertificateAuthority

        # pylint: enable=import-outside-toplevel

        loaded_cas = {}
        certs = fixture_data["certs"]
        for cert_name, cert_data in sorted(certs.items(), key=lambda t: (t[1]["type"], t[0])):
            if cert_data["type"] == "ca":
                if not cert_data["key_filename"]:
                    continue  # CA without private key (e.g. real-world CA)

                name = cert_data["name"]
                cert = CertificateAuthority(name=name, private_key_path=f"{name}.key")
                loaded_cas[cert.name] = cert
            else:
                if cert_data["cat"] != "generated":
                    continue  # Imported cert

                csr_path = os.path.join(ca_settings.CA_DIR, cert_data["csr_filename"])
                with open(csr_path, "r", encoding="utf-8") as stream:
                    csr = stream.read()
                profile = cert_data.get("profile", ca_settings.CA_DEFAULT_PROFILE)
                cert = Certificate(ca=loaded_cas[cert_data["ca"]], csr=csr, profile=profile)

            with open(os.path.join(ca_settings.CA_DIR, cert_data["pub_filename"]), "rb") as stream:
                pem = stream.read()
            cert.update_certificate(x509.load_pem_x509_certificate(pem))

            cert.save()

            if cert_data["type"] == "ca":
                password = cert_data.get("password")
                if password is not None:
                    password = password.encode("utf-8")
                cert.generate_ocsp_key(password=password)
        # Set parent relationships of CAs
        for cert_name, cert_data in certs.items():
            if cert_data["type"] == "ca" and cert_data.get("parent"):
                ca = CertificateAuthority.objects.get(name=cert_name)
                ca.parent = CertificateAuthority.objects.get(name=cert_data["parent"])
                ca.save()

        # create admin user for login
        User = get_user_model()  # pylint: disable=invalid-name  # django standard
        User.objects.create_superuser("user", "user@example.com", "nopass")

        return loaded_cas

    def handle(self, args):
        os.environ["DJANGO_CA_SECRET_KEY"] = "dummy"

        if "TOX_ENV_DIR" in os.environ:
            # insert ca/ into path, otherwise it won't find test_settings in django project
            sys.path.insert(0, str(config.SRC_DIR))

            os.environ["DJANGO_CA_SKIP_LOCAL_CONFIG"] = "1"
            os.environ["CA_DIR"] = os.environ["TOX_ENV_DIR"]
            os.environ["SQLITE_NAME"] = os.path.join(os.environ["TOX_ENV_DIR"], "db.sqlite3")

        self.setup_django("ca.settings")

        # pylint: disable=ungrouped-imports; have to call setup_django() first
        # pylint: disable=import-outside-toplevel; have to call setup_django() first
        from django.core.management import call_command as manage

        from django_ca import ca_settings
        from django_ca.utils import ca_storage

        # pylint: enable=ungrouped-imports,import-outside-toplevel

        print("Creating database...", end="")
        manage("migrate", verbosity=0)
        ok()

        if not os.path.exists(ca_settings.CA_DIR):
            os.makedirs(ca_settings.CA_DIR)

        # NOTE: We pass SKIP_SELENIUM_TESTS=y as environment, because otherwise test_settings will complain
        #       that the driver isn't there, when in fact we're not running any tests.
        # NOTE: Invoke dev.py as a subscript, because recreate-fixtures **requires**
        #       DJANGO_SETTINGS_MODULE=ca.test_settings (b/c it writes to the database and this script writes
        #       the same certs, so you'd get a UniqueConstraint error. The test test_settings use an in-memory
        #       database)
        print("Creating fixture data...", end="")
        subprocess.check_call(
            [
                "python",
                "dev.py",
                "recreate-fixtures",
                "--no-delay",
                "--no-ocsp",
                "--no-contrib",
                "--ca-validity=3650",
                "--cert-validity=732",
                "--quiet",
                f"--dest={ca_settings.CA_DIR}",
            ],
            env=dict(os.environ, SKIP_SELENIUM_TESTS="y"),
        )
        with open(os.path.join(ca_settings.CA_DIR, "cert-data.json"), encoding="utf-8") as stream:
            fixture_data = json.load(stream)
        ok()

        print("Saving fixture data to database.", end="")
        loaded_cas = self.save_fixture_data(ca_settings, fixture_data)
        ok()

        self.output_info(ca_settings.CA_DIR, ca_storage, loaded_cas, fixture_data["certs"], args.base_url)
