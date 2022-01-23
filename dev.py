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

"""Various commands used in development."""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import traceback
import warnings

import packaging.version
import pkg_resources

import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import django
from django.core.exceptions import ImproperlyConfigured

from common import CADIR
from common import ROOTDIR
from common import bold
from common import error
from common import ok
from common import setup_django

sys.path.insert(0, os.path.join(ROOTDIR, "devscripts"))

from dev.config import DOCKER_CONFIG  # NOQA: E402 # requires devscripts in path

test_base = argparse.ArgumentParser(add_help=False)
test_base.add_argument("-s", "--suites", default=[], nargs="+", help="Modules to test (e.g. tests_modules).")
selenium_grp = test_base.add_argument_group("Selenium tests")
selenium_grp.add_argument(
    "--no-selenium",
    dest="selenium",
    action="store_false",
    default=True,
    help="Do not run selenium tests at all.",
)
selenium_grp.add_argument(
    "-p",
    "--no-virtual-display",
    dest="virtual_display",
    action="store_false",
    default=True,
    help="Do not run tests in virtual display.",
)

parser = argparse.ArgumentParser(description="Helper-script for various tasks during development.")
commands = parser.add_subparsers(dest="command")
cq_parser = commands.add_parser("code-quality", help="Run various checks for coding standards.")
dt_parser = commands.add_parser("docker-test", help="Build the Docker image using various base images.")
dt_parser.add_argument(
    "-i",
    "--image",
    action="append",
    dest="images",
    choices=DOCKER_CONFIG["alpine-images"],
    metavar=DOCKER_CONFIG["metavar"],
    help="Base images to test on, may be given multiple times.",
)
dt_parser.add_argument(
    "--no-cache", default=False, action="store_true", help="Use Docker cache to speed up builds."
)
dt_parser.add_argument(
    "--fail-fast", action="store_true", default=False, help="Stop if any docker process fails."
)
dt_parser.add_argument("--keep-image", action="store_true", default=False, help="Do not remove images.")

test_parser = commands.add_parser("test", parents=[test_base])
cov_parser = commands.add_parser("coverage", parents=[test_base])
cov_parser.add_argument(
    "-f",
    "--format",
    choices=["html", "text"],
    default="html",
    help="Write coverage report as text (default: %(default)s).",
)
cov_parser.add_argument(
    "--fail-under",
    type=int,
    default=100,
    metavar="[0-100]",
    help="Fail if coverage is below given percentage (default: %(default)s%%).",
)

demo_parser = commands.add_parser("init-demo", help="Initialize the demo data.")
demo_parser.add_argument(
    "--base-url", metavar="URL", default="http://localhost:8000/", help="Base URL for CRL/OCSP URLs."
)

commands.add_parser("collectstatic", help="Collect and remove static files.")
commands.add_parser("clean", help="Remove generated files.")
args = parser.parse_args()


def test(suites):
    """Run named test suites (or all of them)."""
    # pylint: disable=import-outside-toplevel; imported here so that script runs without django
    import django
    from django.core.management import call_command  # pylint: disable=redefined-outer-name

    # pylint: enable=import-outside-toplevel

    if not args.virtual_display:
        os.environ["VIRTUAL_DISPLAY"] = "n"

    # Set up warnings
    warnings.filterwarnings(action="always")  # print all warnings
    if sys.version_info[:2] >= (3, 10) and django.VERSION[:2] < (4, 0):  # pragma: only django<=4.0
        # This warning only occurs in Python 3.10 and is fixed in Django 4.0:
        #   https://github.com/django/django/commit/623c8cd8f41a99f22d39b264f7eaf7244417000b
        warnings.filterwarnings(
            action="ignore",
            message="There is no current event loop",
            category=DeprecationWarning,
            module="django.utils.asyncio",
        )
    warnings.filterwarnings(action="error", module="django_ca")  # turn our warnings into errors

    os.chdir(CADIR)
    sys.path.insert(0, CADIR)

    print("Testing with:")
    print("* Python: ", sys.version.replace("\n", ""))
    installed_versions = {p.project_name: p.version for p in pkg_resources.working_set}
    for pkg in sorted(["Django", "acme", "cryptography", "celery", "idna"]):
        print(f"* {pkg}: {installed_versions[pkg]}")

    suites = ["django_ca.tests.%s" % s.strip(".") for s in suites]

    call_command("test", *suites, parallel=True)


def exclude_versions(cov, sw, current_version, pragma_version, version_str):
    """
    Parameters
    ----------
    sw : str
    current_version
        The currently used version.
    pragma_version
        The version to add pragmas for.
    version_str:
        Same as `version` but as ``str``.
    """

    if current_version == pragma_version:
        cov.exclude(r"pragma: only %s>%s" % (sw, version_str))
        cov.exclude(r"pragma: only %s<%s" % (sw, version_str))

        cov.exclude(r"pragma: %s<%s branch" % (sw, version_str))
        cov.exclude(r"pragma: %s!=%s" % (sw, version_str))

        # branches
        cov.exclude(r"pragma: %s>=%s" % (sw, version_str), which="partial")
        cov.exclude(r"pragma: %s<=%s" % (sw, version_str), which="partial")

        # completely exclude pragma branches that just don't match.
        # For example, when running python 3.9:
        #
        # if sys.version_info[:2] > (3, 9):  # pragma: py>3.9 branch
        #     print("Only python 3.10 or later")
        #
        # --> just completely exclude the block, as it is never executed
        cov.exclude(r"pragma: %s>%s branch" % (sw, version_str))
        cov.exclude(r"pragma: %s<%s branch" % (sw, version_str))
    else:
        cov.exclude(r"pragma: only %s==%s" % (sw, version_str))
        cov.exclude(r"pragma: %s!=%s" % (sw, version_str), which="partial")

        if current_version < pragma_version:
            cov.exclude(r"pragma: only %s>=%s" % (sw, version_str))
            cov.exclude(r"pragma: only %s>%s" % (sw, version_str))

            # Branches that run in the current version
            cov.exclude(r"pragma: %s<%s branch" % (sw, version_str), which="partial")
            cov.exclude(r"pragma: %s<=%s branch" % (sw, version_str), which="partial")

            # Completely exclude branches only used in *newer* versions. For example, if you use Python 3.8:
            #
            # if sys.version_info[:2] > (3, 9):  # pragma: py>3.9 branch
            #     print("Only python 3.9 or later")
            #
            # --> The branch is never executed on Python 3.8.
            cov.exclude(r"pragma: %s>%s branch" % (sw, version_str))
            cov.exclude(r"pragma: %s>=%s branch" % (sw, version_str))

        if current_version > pragma_version:
            cov.exclude(r"pragma: only %s<=%s" % (sw, version_str))
            cov.exclude(r"pragma: only %s<%s" % (sw, version_str))

            # Branches that run in the current version
            cov.exclude(r"pragma: %s>%s branch" % (sw, version_str), which="partial")
            cov.exclude(r"pragma: %s>=%s branch" % (sw, version_str), which="partial")

            # Completely exclude branches only used in *older* versions. For example, if you use Python 3.9:
            #
            # if sys.version_info[:2] < (3, 9):  # pragma: py<3.9 branch
            #     print("Only before Python 3.9")
            #
            # --> The branch is never executed on Python 3.9.
            cov.exclude(r"pragma: %s<%s branch" % (sw, version_str))
            cov.exclude(r"pragma: %s<=%s branch" % (sw, version_str))


if args.command == "test":
    if not args.selenium:
        os.environ["SKIP_SELENIUM_TESTS"] = "y"

    setup_django()
    test(args.suites)
elif args.command == "coverage":
    import coverage

    if "TOX_ENV_DIR" in os.environ:
        report_dir = os.path.join(os.environ["TOX_ENV_DIR"], "coverage")
        data_file = os.path.join(os.environ["TOX_ENV_DIR"], ".coverage")
    else:
        report_dir = os.path.join(ROOTDIR, "docs", "build", "coverage")
        data_file = None

    if not args.selenium:
        os.environ["SKIP_SELENIUM_TESTS"] = "y"

    cov = coverage.Coverage(
        data_file=data_file,
        cover_pylib=False,
        branch=True,
        source=["django_ca"],
        omit=[
            "*migrations/*",
            "*/tests/tests*",
        ],
    )

    # exclude python version specific code
    py_versions = [(3, 5), (3, 6), (3, 7), (3, 8), (3, 9), (3, 10)]
    for version in py_versions:
        version_str = ".".join([str(v) for v in version])
        exclude_versions(cov, "py", sys.version_info[:2], version, version_str)

    # exclude django-version specific code
    django_versions = [(2, 2), (3, 0), (3, 1), (4, 0)]
    for version in django_versions:
        version_str = ".".join([str(v) for v in version])
        exclude_versions(cov, "django", django.VERSION[:2], version, version_str)

    # exclude cryptography-version specific code
    this_version = packaging.version.parse(cryptography.__version__).release[:2]
    cryptography_versions = [(3, 3), (3, 4), (35, 0), (36, 0)]
    for ver in cryptography_versions:
        version_str = ".".join([str(v) for v in ver])
        exclude_versions(cov, "cryptography", this_version, ver, version_str)

    cov.start()

    setup_django()
    test(args.suites)

    cov.stop()
    cov.save()

    if args.format == "text":
        total_coverage = cov.report()
    else:
        total_coverage = cov.html_report(directory=report_dir)
    if total_coverage < args.fail_under:
        if args.fail_under == 100.0:
            print("Error: Coverage was only %.2f%% (should be 100%%)." % total_coverage)
        else:
            print(
                "Error: Coverage was only %.2f%% (should be above %.2f%%)."
                % (total_coverage, args.fail_under)
            )
        sys.exit(2)  # coverage cli utility also exits with 2

elif args.command == "code-quality":
    files = ["ca/", "devscripts/", "docs/source/"] + glob.glob("*.py")
    print("+ isort --check-only --diff %s" % " ".join(files))
    try:
        subprocess.run(["isort", "--check-only", "--diff"] + files, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

    print("+ flake8 %s" % " ".join(files))
    try:
        subprocess.run(["flake8"] + files, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
    print("")

    print("+ black --check %s" % " ".join(files))
    try:
        subprocess.run(["black", "--check"] + files, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
    print("")

    py = ["python", "-Wd"]

    # Django 4.0 changes the default to True. Remove USE_L10N setting once support for Django<4.0 is dropped.
    #   https://docs.djangoproject.com/en/4.0/releases/4.0/#miscellaneous
    py += ["-W", "ignore:The USE_L10N setting is deprecated."]  # pragma: only django<4.0

    # Django 3.2 adds AppConfig discovery. Remove default_app_config once support for Django<3.2 is dropped.
    #   https://docs.djangoproject.com/en/dev/releases/3.2/#automatic-appconfig-discovery
    py += ["-W", "ignore:'django_ca' defines default_app_config"]  # pragma: only django<3.2

    cmd = py + ["manage.py", "check"]
    print(f"+ {' '.join(cmd)}")  # pragma: only py<3.8; use shlex.join() instead
    try:
        subprocess.run(cmd, cwd=CADIR, check=True, env=dict(os.environ, DJANGO_CA_SECRET_KEY="dummy"))
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

    cmd = py + ["manage.py", "makemigrations", "--check"]
    print(f"+ {' '.join(cmd)}")  # pragma: only py<3.8; use shlex.join() instead
    try:
        subprocess.run(cmd, cwd=CADIR, check=True, env=dict(os.environ, DJANGO_CA_SECRET_KEY="dummy"))
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
elif args.command == "docker-test":
    docker_runs = []

    images = args.images or DOCKER_CONFIG["alpine-images"]
    for image in images:
        print("### Testing %s ###" % image)
        tag = "django-ca-test-%s" % image

        cmd = [
            "docker",
            "build",
        ]

        if args.no_cache:
            cmd.append("--no-cache")
        if image != "default":
            cmd += [
                "--build-arg",
                "IMAGE=%s" % image,
            ]

        cmd += [
            "-t",
            tag,
        ]
        cmd.append(".")

        print(" ".join(cmd))

        logdir = ".docker"
        logpath = os.path.join(logdir, "%s.log" % image)
        if not os.path.exists(logdir):
            os.makedirs(logdir)

        env = dict(os.environ, DOCKER_BUILDKIT="1")

        try:
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env) as p, open(
                logpath, "bw"
            ) as stream:
                while True:
                    byte = p.stdout.read(1)
                    if byte:
                        sys.stdout.buffer.write(byte)
                        sys.stdout.flush()
                        stream.write(byte)
                        # logfile.flush()
                    else:
                        break

            if p.returncode == 0:
                ok_str = "# %s passed. #" % image
                ok("%s\n%s\n%s\n\n" % ("#" * len(ok_str), ok_str, "#" * len(ok_str)))
                docker_runs.append(
                    {
                        "image": image,
                        "success": True,
                        "error": "",
                    }
                )
            else:
                failed_str = "# %s failed: return code %s. #" % (image, p.returncode)
                error("%s\n%s\n%s\n\n" % ("#" * len(failed_str), failed_str, "#" * len(failed_str)))
                docker_runs.append(
                    {
                        "image": image,
                        "success": False,
                        "error": "return code: %s" % p.returncode,
                    }
                )

        except Exception as e:  # pylint: disable=broad-except; to make sure we test all images
            msg = "%s: %s: %s" % (image, type(e).__name__, e)
            docker_runs.append(
                {
                    "image": image,
                    "success": False,
                    "error": msg,
                }
            )

            error("\n%s\n" % msg)
            if args.fail_fast:
                sys.exit(1)
        finally:
            if not args.keep_image:
                subprocess.call(["docker", "image", "rm", tag])

    print("\nSummary of test runs:")
    for run in docker_runs:
        if run["success"]:
            ok("  %s: passed." % run["image"])
        else:
            error("  %s: %s" % (run["image"], run["error"]))

    failed_images = [r["image"] for r in docker_runs if not r["success"]]
    if not failed_images:
        ok("\nCongratulations :)")
    else:
        error("\nSome images failed (%s)" % ", ".join(failed_images))
        sys.exit(1)

elif args.command == "init-demo":
    os.environ["DJANGO_CA_SECRET_KEY"] = "dummy"

    if "TOX_ENV_DIR" in os.environ:
        os.environ["DJANGO_CA_SKIP_LOCAL_CONFIG"] = "1"
        os.environ["CA_DIR"] = os.environ["TOX_ENV_DIR"]
        os.environ["SQLITE_NAME"] = os.path.join(os.environ["TOX_ENV_DIR"], "db.sqlite3")

    try:
        setup_django("ca.settings")
    except ImproperlyConfigured:
        # Cannot import settings, probably because localsettings.py wasn't created.
        traceback.print_exc()
        localsettings = os.path.join(CADIR, "ca", "localsettings.py")
        print(
            """
Could not configure settings! Have you created localsettings.py?

Please create %(localsettings)s from %(example)s and try again."""
            % {
                "localsettings": localsettings,
                "example": "%s.example" % localsettings,
            }
        )
        sys.exit(1)

    # pylint: disable=ungrouped-imports; have to call setup_django() first
    from django.contrib.auth import get_user_model
    from django.core.files.base import ContentFile
    from django.core.management import call_command as manage
    from django.urls import reverse

    from django_ca import ca_settings
    from django_ca.models import Certificate
    from django_ca.models import CertificateAuthority
    from django_ca.utils import ca_storage

    # pylint: enable=ungrouped-imports

    User = get_user_model()

    print("Creating database...", end="")
    manage("migrate", verbosity=0)
    ok()

    if not os.path.exists(ca_settings.CA_DIR):
        os.makedirs(ca_settings.CA_DIR)

    # NOTE: We pass SKIP_SELENIUM_TESTS=y as environment, because otherwise test_settings will complain that
    #       the driver isn't there, when in fact we're not running any tests.
    print("Creating fixture data...", end="")
    subprocess.check_call(
        [
            "python",
            "recreate-fixtures.py",
            "--no-delay",
            "--no-ocsp",
            "--no-contrib",
            "--ca-validity=3650",
            "--cert-validity=732",
            "--dest=%s" % ca_settings.CA_DIR,
        ],
        env=dict(os.environ, SKIP_SELENIUM_TESTS="y"),
    )
    with open(os.path.join(ca_settings.CA_DIR, "cert-data.json")) as stream:
        fixture_data = json.load(stream)
    ok()

    print("Saving fixture data to database.", end="")
    loaded_cas = {}
    certs = fixture_data["certs"]
    for cert_name, cert_data in sorted(certs.items(), key=lambda t: (t[1]["type"], t[0])):
        if cert_data["type"] == "ca":
            if not cert_data["key_filename"]:
                continue  # CA without private key (e.g. real-world CA)

            name = cert_data["name"]
            path = "%s.key" % name

            with open(os.path.join(ca_settings.CA_DIR, cert_data["key_filename"]), "rb") as stream:
                pkey = stream.read()

            c = CertificateAuthority(name=name, private_key_path=path)
            loaded_cas[c.name] = c
        else:
            if cert_data["cat"] != "generated":
                continue  # Imported cert

            with open(os.path.join(ca_settings.CA_DIR, cert_data["csr_filename"]), "r") as stream:
                csr = stream.read()
            profile = cert_data.get("profile", ca_settings.CA_DEFAULT_PROFILE)
            c = Certificate(ca=loaded_cas[cert_data["ca"]], csr=csr, profile=profile)

        with open(os.path.join(ca_settings.CA_DIR, cert_data["pub_filename"]), "rb") as stream:
            pem = stream.read()
        c.update_certificate(x509.load_pem_x509_certificate(pem, default_backend()))

        c.save()

        if cert_data["type"] == "ca":
            password = cert_data.get("password")
            if password is not None:
                password = password.encode("utf-8")
            c.generate_ocsp_key(password=password)

    # Set parent relationships of CAs
    for cert_name, cert_data in certs.items():
        if cert_data["type"] == "ca" and cert_data.get("parent"):
            ca = CertificateAuthority.objects.get(name=cert_name)
            ca.parent = CertificateAuthority.objects.get(name=cert_data["parent"])
            ca.save()

    # create admin user for login
    User.objects.create_superuser("user", "user@example.com", "nopass")

    ok()

    # create a chain file for the child
    chain = loaded_cas["child"].pub.pem + loaded_cas["root"].pub.pem
    chain_path = ca_storage.path(ca_storage.save("child-chain.pem", ContentFile(chain)))

    cwd = os.getcwd()
    rel = lambda p: os.path.relpath(p, cwd)  # NOQA
    root_ca_path = ca_storage.path(certs["root"]["pub_filename"])
    child_ca_path = ca_storage.path(certs["child"]["pub_filename"])

    root_cert_path = ca_storage.path(certs["root-cert"]["pub_filename"])
    child_cert_path = ca_storage.path(certs["child-cert"]["pub_filename"])

    ocsp_url = "%s%s" % (
        args.base_url.rstrip("/"),
        reverse("django_ca:ocsp-cert-post", kwargs={"serial": certs["child"]["serial"]}),
    )

    print("")
    print("* All certificates are in %s." % bold(ca_settings.CA_DIR))
    ok("* Start webserver with the admin interface:")
    print('  * Run "%s"' % bold("python ca/manage.py runserver"))
    print("  * Visit %s" % bold("%sadmin/" % args.base_url))
    print("  * User/Password: %s / %s" % (bold("user"), bold("nopass")))
    ok("* Create CRLs with:")
    print(
        "  * %s"
        % bold("python ca/manage.py dump_crl -f PEM --ca %s > root.crl" % loaded_cas["root"].serial[:11])
    )
    print(
        "  * %s"
        % bold("python ca/manage.py dump_crl -f PEM --ca %s > child.crl" % loaded_cas["child"].serial[:11])
    )
    ok("* Verify with CRL:")
    print(
        "  * %s"
        % bold(
            "openssl verify -CAfile %s -CRLfile root.crl -crl_check %s"
            % (rel(root_ca_path), rel(root_cert_path))
        )
    )
    print(
        "  * %s"
        % bold(
            "openssl verify -CAfile %s -crl_download -crl_check %s" % (rel(root_ca_path), rel(root_cert_path))
        )
    )
    ok("* Verify certificate with OCSP:")
    print(
        "    %s"
        % bold(
            "openssl ocsp -CAfile %s -issuer %s -cert %s -url %s -resp_text"
            % (rel(root_ca_path), rel(child_ca_path), rel(child_cert_path), ocsp_url)
        )
    )

elif args.command == "collectstatic":
    setup_django("ca.settings")

    # pylint: disable=ungrouped-imports; have to call setup_django() first
    from django.contrib.staticfiles.finders import get_finders
    from django.core.management import call_command

    # pylint: enable=ungrouped-imports

    call_command("collectstatic", interactive=False)

    locations = set()
    for finder in get_finders():
        for path, storage in finder.list([]):
            locations.add(storage.location)

    for location in locations:
        print('rm -r "%s"' % location)
        shutil.rmtree(location)
elif args.command == "clean":
    base = os.path.dirname(os.path.abspath(__file__))

    def rm(*paths):  # pylint: disable=invalid-name; rm() is just descriptive
        """Remove a file/dir if it exists."""
        rm_path = os.path.join(base, *paths)
        if not os.path.exists(rm_path):
            return
        if os.path.isdir(rm_path):
            print("rm -r", rm_path)
            shutil.rmtree(rm_path)
        else:
            print("rm", rm_path)
            os.remove(rm_path)

    rm("pip-selfcheck.json")
    rm("geckodriver.log")
    rm("docs", "build")
    rm(".tox")
    rm("ca", "files")
    rm("ca", "geckodriver.log")
    rm("dist")
    rm("build")
    rm(".coverage")
    rm(".docker")
    rm(".mypy_cache")

    for root, dirs, files in os.walk(base, topdown=False):
        for name in files:
            if name.endswith(".pyc") or name.endswith(".sqlite3"):
                rm(root, name)
        for name in dirs:
            if name == "__pycache__" or name.endswith(".egg-info"):
                rm(root, name)

else:
    parser.print_help()
