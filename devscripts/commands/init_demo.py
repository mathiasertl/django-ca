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
import argparse
import json
import os
import subprocess
import sys
import types
import typing
from typing import Any, Dict, Union

from cryptography import x509

from django.core.files.storage import Storage

from devscripts import config
from devscripts.commands import DevCommand
from devscripts.out import bold

if typing.TYPE_CHECKING:
    from django_ca.models import CertificateAuthority
    from django_ca.tests.base.typehints import CertFixtureData, FixtureData


class Command(DevCommand):
    """Initialize this project with useful example data."""

    modules = (("termcolor", "termcolor"),)
    termcolor: types.ModuleType

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--base-url", metavar="URL", default="http://localhost:8000/", help="Base URL for CRL/OCSP URLs."
        )

    def path(self, ca_storage: Storage, certs: "CertFixtureData", name: str) -> str:
        """Get a file path."""
        return os.path.relpath(ca_storage.path(certs[name]["pub_filename"]), os.getcwd())

    def ok(self, msg: str = " OK.", **kwargs: Any) -> None:  # pylint: disable=invalid-name
        """Just print "OK" in green."""
        print(self.termcolor.colored(msg, "green"), **kwargs)

    def output_info(  # pylint: disable=too-many-locals
        self,
        ca_dir: str,
        ca_storage: Storage,
        loaded_cas: Dict[str, "CertificateAuthority"],
        certs: "CertFixtureData",
        base_url: str,
    ) -> None:
        """Output demo info to the user."""
        from django.urls import reverse  # pylint: disable=import-outside-toplevel  # see handle() imports

        base_url = base_url.rstrip("/")
        ca_names = ("root", "child", "dsa", "ec", "ed448", "ed25519")
        cas = [
            (ca, self.path(ca_storage, certs, ca), self.path(ca_storage, certs, f"{ca}-cert"))
            for ca in ca_names
        ]

        dump_crl = "python ca/manage.py dump_crl"
        child_serial = loaded_cas["child"].serial[:11]
        child_bundle = "child.bundle.pem"

        print("")
        print(f"* All certificates are in {bold(ca_dir)}")
        self.ok("* Start webserver with the admin interface:")
        print(f'  * Run "{bold("python ca/manage.py runserver")}"')
        print(f"  * Visit {bold(f'{base_url}/admin/')}")
        print(f"  * User/Password: {bold('user')} / {bold('nopass')}")

        self.ok("* Create child bundle:")
        print(f"  * {bold(f'python ca/manage.py dump_ca --bundle {child_serial}')} > {child_bundle}")

        self.ok("* Create CRLs with:")
        for ca, _ca_path, _cert_path in cas:
            serial = loaded_cas[ca].serial[:11]
            print(f"  * {bold(f'{dump_crl} -f PEM --ca {serial} > {ca}.crl')}")

        self.ok("* Verify with pre-generated CRL:")
        for ca, ca_path, cert_path in cas:
            if ca == "child":
                ca_path = child_bundle
            print(f"  * {bold(f'openssl verify -CAfile {ca_path} -CRLfile {ca}.crl -crl_check {cert_path}')}")

        self.ok("* Verify with auto-downloaded CRL:")
        for ca, ca_path, cert_path in cas:
            if ca == "child":
                ca_path = child_bundle
            print(f"  * {bold(f'openssl verify -CAfile {ca_path} -crl_download -crl_check {cert_path}')}")

        self.ok("* Verify certificate with OCSP:")
        for ca, ca_path, cert_path in cas:
            ocsp_post_path = reverse("django_ca:ocsp-cert-post", kwargs={"serial": certs[ca]["serial"]})
            ocsp_url = f"{base_url}{ocsp_post_path}"
            if ca == "child":
                ca_path = child_bundle

            cmd = f"openssl ocsp -CAfile {ca_path} -issuer {ca_path} -cert {cert_path} -url {ocsp_url} -resp_text"  # noqa: E501
            print(f"  * {bold(cmd)}")

    def save_fixture_data(
        self, ca_settings: types.ModuleType, fixture_data: "FixtureData"
    ) -> Dict[str, "CertificateAuthority"]:
        """Save loaded fixture data to database."""
        # pylint: disable=import-outside-toplevel  # see handle() imports
        from django.contrib.auth import get_user_model

        from django_ca.models import Certificate, CertificateAuthority

        # pylint: enable=import-outside-toplevel

        loaded_cas = {}
        certs = fixture_data["certs"]
        for cert_name, cert_data in sorted(certs.items(), key=lambda t: (t[1]["type"], t[0])):
            cert: Union[CertificateAuthority, Certificate]  # facilitate type hinting later
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

            # Generate OCSP key after saving, as cert.pub is still `bytes` before `save()`.
            if isinstance(cert, CertificateAuthority):
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

    def handle(self, args: argparse.Namespace) -> None:
        os.environ["DJANGO_CA_SECRET_KEY"] = "dummy"

        if "TOX_ENV_DIR" in os.environ:
            # insert ca/ into path, otherwise it won't find test_settings in django project
            sys.path.insert(0, str(config.SRC_DIR))

            os.environ["DJANGO_CA_SKIP_LOCAL_CONFIG"] = "1"
            os.environ["CA_DIR"] = os.environ["TOX_ENV_DIR"]
            os.environ["SQLITE_NAME"] = os.path.join(os.environ["TOX_ENV_DIR"], "db.sqlite3")

        self.setup_django("ca.settings")

        # pylint: disable=import-outside-toplevel; have to call setup_django() first
        from django.core.management import call_command as manage

        from django_ca import ca_settings
        from django_ca.utils import ca_storage

        # pylint: enable=import-outside-toplevel

        print("Creating database...", end="")
        manage("migrate", verbosity=0)
        self.ok()

        if not os.path.exists(ca_settings.CA_DIR):
            os.makedirs(ca_settings.CA_DIR)

        # NOTE: Invoke dev.py as a subscript, because recreate-fixtures **requires**
        #       DJANGO_SETTINGS_MODULE=ca.test_settings (b/c it writes to the database and this script writes
        #       the same certs, so you'd get a UniqueConstraint error. The test test_settings use an in-memory
        #       database)
        print("Creating fixture data...", end="")
        subprocess.check_call(
            [
                "python",
                "dev.py",
                "--quiet",
                "recreate-fixtures",
                "--no-delay",
                "--no-ocsp",
                "--no-contrib",
                "--ca-validity=3650",
                "--cert-validity=732",
                f"--dest={ca_settings.CA_DIR}",
            ]
        )
        with open(os.path.join(ca_settings.CA_DIR, "cert-data.json"), encoding="utf-8") as stream:
            fixture_data = json.load(stream)
        self.ok()

        print("Saving fixture data to database.", end="")
        loaded_cas = self.save_fixture_data(ca_settings, fixture_data)
        self.ok()

        self.output_info(ca_settings.CA_DIR, ca_storage, loaded_cas, fixture_data["certs"], args.base_url)
