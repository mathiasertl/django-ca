#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

from __future__ import print_function

import argparse
import os
import subprocess
import sys
import warnings

import packaging.version

import cryptography

import django

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

suites_parser = argparse.ArgumentParser(add_help=False)
suites_parser.add_argument('-s', '--suites', default=[], nargs='+',
                           help="Modules to test (e.g. tests_modules).")

parser = argparse.ArgumentParser(
    description='Helper-script for various tasks during development.'
)
commands = parser.add_subparsers(dest='command')
cq_parser = commands.add_parser('code-quality', help='Run various checks for coding standards.')
ti_parser = commands.add_parser('test-imports', help='Import django-ca modules to test dependencies.')
dt_parser = commands.add_parser('docker-test', help='Build the Docker image using various base images.')
dt_parser.add_argument('-i', '--image', action='append', dest='images',
                       help='Base images to test on, may be given multiple times.')
dt_parser.add_argument('-c', '--cache', dest='no_cache', default='True', action='store_false',
                       help='Use Docker cache to speed up builds.')

test_parser = commands.add_parser('test', parents=[suites_parser])
test_parser.add_argument('--recreate-fixtures', action='store_true', default=False,
                         help="Recreate fixtures")

cov_parser = commands.add_parser('coverage', parents=[suites_parser])
cov_parser.add_argument('--fail-under', type=int, default=100, metavar='[0-100]',
                        help='Fail if coverage is below given percentage (default: %(default)s%%).')

demo_parser = commands.add_parser('init-demo', help="Initialize the demo data.")

data_parser = commands.add_parser('update-ca-data', help="Update tables for ca_examples.rst in docs.")

args = parser.parse_args()

_rootdir = os.path.dirname(os.path.realpath(__file__))


def warn(msg, **kwargs):
    print(colored(msg, 'yellow'), **kwargs)


def ok():
    print(colored(' OK.', 'green'))


def abort(msg):
    print(msg)
    sys.exit(1)


def setup_django(settings_module="ca.test_settings"):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", settings_module)
    sys.path.insert(0, os.path.join(_rootdir, 'ca'))

    django.setup()


def test(suites):
    warnings.filterwarnings(action='always')
    warnings.filterwarnings(action='error', module='django_ca')

    # ignore this warning in some modules to get cleaner output
    msg = "Using or importing the ABCs from 'collections' instead of from 'collections.abc' is deprecated"
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='webtest.lint',
                            message=msg)
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='markupsafe',
                            message=msg)
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='jinja2',
                            message=msg)

    # filter some webtest warnings
    msg2 = r'urllib.parse.splithost\(\) is deprecated as of 3.8, use urllib.parse.urlparse\(\) instead'
    msg3 = r'urllib.parse.splittype\(\) is deprecated as of 3.8, use urllib.parse.urlparse\(\) instead'
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='webtest.*',
                            message=msg2)
    warnings.filterwarnings(action='ignore', category=DeprecationWarning, module='webtest.*',
                            message=msg3)

    work_dir = os.path.join(_rootdir, 'ca')

    os.chdir(work_dir)
    sys.path.insert(0, work_dir)

    suites = ['django_ca.tests.%s' % s for s in suites]

    from django.core.management import call_command
    call_command('test', *suites)


def exclude_versions(cov, sw, this_version, version, version_str):
    if version == this_version:
        cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s>%s' % (sw, version_str))
        cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s<%s' % (sw, version_str))
    else:
        cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s==%s' % (sw, version_str))

        if version > this_version:
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s>=%s' % (sw, version_str))
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s>%s' % (sw, version_str))

        if version < this_version:
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s<=%s' % (sw, version_str))
            cov.exclude(r'(pragma|PRAGMA)[:\s]?\s*only %s<%s' % (sw, version_str))


if args.command == 'test':
    setup_django()
    if args.recreate_fixtures:
        os.environ['UPDATE_FIXTURES'] = '1'
        test(['tests_managers'])
    else:
        test(args.suites)
elif args.command == 'coverage':
    import coverage

    report_dir = os.path.join(_rootdir, 'docs', 'build', 'coverage')
    cov = coverage.Coverage(cover_pylib=False, branch=True, source=['django_ca'],
                            omit=['*migrations/*', '*/tests/tests*', ])

    # exclude python-version specific code
    if PY2:
        cov.exclude('only py3')
    else:
        cov.exclude('only py2')

    # exclude code that requires SCT
    from cryptography.hazmat.backends import default_backend
    if not default_backend()._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER:
        cov.exclude(r'pragma:\s*only SCT')

    # exclude django-version specific code
    django_versions = [(1, 11), (2, 0), (2, 1), (2, 2), (2, 3)]

    for version in django_versions:
        version_str = '.'.join([str(v) for v in version])
        exclude_versions(cov, 'django', django.VERSION[:2], version, version_str)

    # exclude cryptography-version specific code
    this_version = packaging.version.parse(cryptography.__version__).release[:2]
    cryptography_versions = [(2, 2), (2, 3), (2, 4), (2, 5), (2, 6)]
    for ver in cryptography_versions:
        version_str = '.'.join([str(v) for v in ver])
        exclude_versions(cov, 'cryptography', this_version, ver, version_str)

    cov.start()

    setup_django()
    test(args.suites)

    cov.stop()
    cov.save()

    total_coverage = cov.html_report(directory=report_dir)
    if total_coverage < args.fail_under:
        if args.fail_under == 100.0:
            print('Error: Coverage was only %.2f%% (should be 100%%).' % total_coverage)
        else:
            print('Error: Coverage was only %.2f%% (should be above %.2f%%).' % (
                total_coverage, args.fail_under))
        sys.exit(2)  # coverage cli utility also exits with 2

elif args.command == 'code-quality':
    print('isort --check-only --diff -rc ca/ setup.py dev.py')
    status = subprocess.call(['isort', '--check-only', '--diff', '-rc', 'ca/', 'setup.py', 'dev.py'])
    if status != 0:
        sys.exit(status)

    print('flake8 ca/ setup.py dev.py')
    status = subprocess.call(['flake8', 'ca/', 'setup.py', 'dev.py'])
    if status != 0:
        sys.exit(status)

    print('python -Wd manage.py check')
    setup_django('ca.test_settings')
    status = subprocess.call(['python', '-Wd', 'manage.py', 'check'], cwd=os.path.join(_rootdir, 'ca'))
    if status != 0:
        sys.exit(status)
elif args.command == 'test-imports':
    setup_django('ca.settings')

    # useful when run in docker-test, where localsettings uses YAML
    from django.conf import settings  # NOQA

    # import some modules - if any dependency is not installed, this will fail
    from django_ca import utils, models, views, extensions, subject  # NOQA

elif args.command == 'docker-test':
    images = args.images or [
        'default',

        # Currently supported Alpine releases:
        #   https://wiki.alpinelinux.org/wiki/Alpine_Linux:Releases

        'python:2.7-alpine3.9',
        'python:3.5-alpine3.9',
        'python:3.6-alpine3.9',
        'python:3.7-alpine3.9',
        'python:2.7-alpine3.8',
        'python:3.5-alpine3.8',
        'python:3.6-alpine3.8',
        'python:3.7-alpine3.8',
        'python:2.7-alpine3.7',
        'python:3.5-alpine3.7',
        'python:3.6-alpine3.7',
        'python:3.7-alpine3.7',
    ]

    for image in images:
        print('### Testing %s ###' % image)
        tag = 'django-ca-test-%s' % image

        cmd = ['docker', 'build', ]

        if args.no_cache:
            cmd.append('--no-cache')
        if image != 'default':
            cmd += ['--build-arg', 'IMAGE=%s' % image, ]

        cmd += ['-t', tag, ]
        cmd.append('.')

        print(' '.join(cmd))

        try:
            subprocess.check_call(cmd)
        except Exception:
            print('### Failed image is %s' % image)
        finally:
            subprocess.call(['docker', 'image', 'rm', tag])

elif args.command == 'init-demo':
    from termcolor import colored

    def green(msg):
        return colored(msg, 'green')

    setup_django('ca.demosettings')
    base_url = 'http://localhost:8000/'

    from django.conf import settings
    from django.contrib.auth import get_user_model
    from django.core.management import call_command as manage
    from django.urls import reverse
    from django.utils.six.moves.urllib.parse import urljoin
    from django_ca import ca_settings
    from django_ca.models import Certificate
    from django_ca.models import CertificateAuthority
    from django_ca.models import Watcher
    from django_ca.subject import Subject
    User = get_user_model()

    def create_cert(name, **kwargs):
        key = os.path.join(ca_settings.CA_DIR, '%s.key' % name)
        csr = os.path.join(ca_settings.CA_DIR, '%s.csr' % name)
        pem = os.path.join(ca_settings.CA_DIR, '%s.pem' % name)
        kwargs.setdefault('subject', Subject())
        kwargs['subject'].setdefault('CN', name)

        if PY2:
            # PY2 does not have subprocess.DEVNULL
            with open(os.devnull, 'w') as devnull:
                subprocess.call(['openssl', 'genrsa', '-out', key, '2048'], stderr=devnull)
        else:
            subprocess.call(['openssl', 'genrsa', '-out', key, '2048'], stderr=subprocess.DEVNULL)

        subprocess.call(['openssl', 'req', '-new', '-key', key, '-out', csr, '-utf8', '-batch'])
        manage('sign_cert', csr=csr, out=pem, **kwargs)
        return key, csr, pem

    if settings.DEBUG is not True:
        abort(colored('Refusing to run if settings.DEBUG != True.', 'red'))

    if os.path.exists(os.path.join('ca', 'db.sqlite3')):
        abort(colored('CA already set up.', 'red'))

    print('Creating database...', end='')
    manage('migrate', verbosity=0)
    ok()

    print('Creating Root CA', end='')
    manage('init_ca', 'Root CA', '/C=AT/ST=Vienna/L=Vienna/O=example/OU=example/CN=ca.example.com',
           pathlen=1, ocsp_url='http://ocsp.ca.example.com',
           issuer_url='http://ca.example.com/ca.crt', issuer_alt_name='https://ca.example.com'
           )
    root_ca = CertificateAuthority.objects.get(name='Root CA')
    ok()

    # generate OCSP certificate
    print('Creating OCSP certificate...', end='')
    ocsp_key, ocsp_csr, ocsp_pem = create_cert(
        'root-ocsp', subject=Subject({'CN': 'localhost'}), profile='ocsp'
    )
    ok()

    # Compute and set CRL URL for the root CA
    root_crl_path = reverse('django_ca:crl', kwargs={'serial': root_ca.serial})
    root_ca.crl_url = urljoin(base_url, root_crl_path)
    root_ca.ocsp_url = urljoin(base_url, reverse('django_ca:ocsp-post-root'))
    root_ca.save()

    # Get OCSP/CRL URL for child CAs
    root_ca_crl_path = reverse('django_ca:ca-crl', kwargs={'serial': root_ca.serial})
    root_ca_crl = urljoin(base_url, root_ca_crl_path)
    root_ca_ocsp_ca_url = urljoin(base_url, reverse('django_ca:ocsp-post-root-ca'))

    print('Creating Intermediate CA...', end='')
    manage(
        'init_ca', 'Intermediate CA', '/C=AT/ST=Vienna/L=Vienna/O=example/OU=example/CN=sub.ca.example.com',
        parent=root_ca, ca_crl_url=root_ca_crl, ca_ocsp_url=root_ca_ocsp_ca_url,
    )
    child_ca = CertificateAuthority.objects.get(name='Intermediate CA')
    ok()

    # generate OCSP certificate
    print('Creating OCSP certificate for intermediate CA...', end='')
    ocsp_key, ocsp_csr, ocsp_pem = create_cert(
        'intermediate-ocsp', subject=Subject({'CN': 'localhost'}), profile='ocsp', ca=child_ca
    )
    ok()

    # Compute and set CRL URL for the child CA
    child_crl_path = reverse('django_ca:crl', kwargs={'serial': child_ca.serial})
    child_ca.crl_url = urljoin(base_url, child_crl_path)
    child_ca.ocsp_url = urljoin(base_url, reverse('django_ca:ocsp-post-intermediate'))
    child_ca.save()

    # Create some client certificates (always trust localhost to ease testing)
    for i in range(1, 10):
        hostname = 'host%s.example.com' % i
        print('Creating certificate for %s...' % hostname, end='')
        create_cert(hostname, alt=['localhost'], ca=child_ca)
        ok()

    # create stunnel.pem
    print('Creating combined certificates file for stunnel...', end='')
    key_path = os.path.join(ca_settings.CA_DIR, 'host1.example.com.key')
    pem_path = os.path.join(ca_settings.CA_DIR, 'host1.example.com.pem')
    stunnel_path = os.path.join(ca_settings.CA_DIR, 'stunnel.pem')
    with open(key_path) as key, open(pem_path) as pem, open(stunnel_path, 'w') as stunnel:
        stunnel.write(key.read())
        stunnel.write(pem.read())

        # cert is signed by intermediate CA, so we need to attach it as well
        stunnel.write(child_ca.pub)

    key_path = os.path.join(ca_settings.CA_DIR, 'host2.example.com.key')
    pem_path = os.path.join(ca_settings.CA_DIR, 'host2.example.com.pem')
    stunnel_path = os.path.join(ca_settings.CA_DIR, 'stunnel-revoked.pem')
    with open(key_path) as key, open(pem_path) as pem, open(stunnel_path, 'w') as stunnel:
        stunnel.write(key.read())
        stunnel.write(pem.read())

        # cert is signed by intermediate CA, so we need to attach it as well
        stunnel.write(child_ca.pub)
    ok()

    print('Create a client certificate...', end='')
    create_cert('client', subject=Subject({'CN': 'First Last'}), cn_in_san=False, alt=['user@example.com'],
                ca=child_ca)
    ok()

    # Revoke host1 and host2
    print('Revoke host2.example.com and host3.example.com...', end='')
    cert = Certificate.objects.get(cn='host2.example.com')
    cert.revoke()
    cert.save()

    cert = Certificate.objects.get(cn='host3.example.com')
    cert.revoke('key_compromise')
    cert.save()
    ok()

    print('Create CRL and OCSP index...', end='')
    crl_path = os.path.join(ca_settings.CA_DIR, 'crl.pem')
    ocsp_index = os.path.join(ca_settings.CA_DIR, 'ocsp_index.txt')
    manage('dump_crl', crl_path)
    manage('dump_ocsp_index', ocsp_index, ca=root_ca)
    ok()

    ca_crl_path = os.path.join(ca_settings.CA_DIR, 'ca_crl.pem')

    # Concat the CA certificate and the CRL, this is required by "openssl verify"
    with open(crl_path) as crl, open(ca_crl_path, 'w') as ca_crl:
        ca_crl.write(root_ca.pub)
        ca_crl.write(crl.read())

    # create a few watchers
    Watcher.from_addr('First Last <user1@example.com>')
    Watcher.from_addr('Second Last <user2@example.com>')

    # create admin user for login
    User.objects.create_superuser('user', 'user@example.com', 'nopass')

    # write public ca cert so it can be used by demo commands below
    ca_crt = os.path.join(ca_settings.CA_DIR, '%s.pem' % root_ca.serial)
    with open(ca_crt, 'w') as outstream:
        outstream.write(root_ca.pub)
    ca_crt = os.path.join(ca_settings.CA_DIR, '%s.pem' % child_ca.serial)
    with open(ca_crt, 'w') as outstream:
        outstream.write(child_ca.pub)

    os.chdir('../')
    cwd = os.getcwd()
    rel = lambda p: os.path.relpath(p, cwd)  # NOQA
    ca_crt = rel(ca_crt)
    host1_pem = rel(os.path.join(ca_settings.CA_DIR, 'host1.example.com.pem'))
    print("")
    print(green('* All certificates are in %s' % rel(ca_settings.CA_DIR)))
    print(green('* Verify with CRL:'))
    print('\topenssl verify -CAfile %s -crl_check %s' % (rel(ca_crl_path), rel(host1_pem)))
    print(green('* Run OCSP responder:'))
    print('\topenssl ocsp -index %s -port 8888 -rsigner %s -rkey %s -CA %s -text' %
          (rel(ocsp_index), rel(ocsp_pem), rel(ocsp_key), ca_crt))
    print(green('* Verify certificate with OCSP:'))
    print('\topenssl ocsp -CAfile %s -issuer %s -cert %s -url %s -resp_text' %
          (ca_crt, ca_crt, host1_pem, base_url))
    print(green('* Start webserver on %s (user: user, password: nopass) with:' % base_url))
    print('\tDJANGO_SETTINGS_MODULE=ca.demosettings python ca/manage.py runserver')

elif args.command == 'update-ca-data':
    setup_django('ca.settings')

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from tabulate import tabulate
    from termcolor import colored

    from django_ca.utils import format_name
    from django_ca.utils import bytes_to_hex
    from django_ca.utils import format_general_names

    docs_base = os.path.join(_rootdir, 'docs', 'source')
    out_base = os.path.join(docs_base, 'generated')
    if not os.path.exists(out_base):
        os.makedirs(out_base)

    def _update_cert_data(prefix, cert_dir, certs, name_header):
        cert_values = {
            'subject': [(name_header, 'Subject', )],
            'issuer': [(name_header, 'Issuer', )],
            'aki': [(name_header, 'Critical', 'Key identifier', 'Issuer', 'Serial')],
            'basicconstraints': [(name_header, 'Critical', 'CA', 'Path length')],
        }

        for filename in sorted(os.listdir(cert_dir), key=lambda f: certs.get(f, {}).get('name', '')):
            if filename not in certs:
                warn('Unknown Cert: %s' % filename)
                continue

            cert_name = certs[filename]['name']

            this_cert_values = {}
            for key, headers in cert_values.items():
                this_cert_values[key] = ['']

            with open(os.path.join(cert_dir, filename), 'rb') as stream:
                cert = x509.load_pem_x509_certificate(stream.read(), backend=default_backend())

                this_cert_values['subject'] = [format_name(cert.subject)]
                this_cert_values['issuer'] = [format_name(cert.issuer)]

                for ext in cert.extensions:
                    value = ext.value
                    critical = '✓' if ext.critical else '✗'

                    if isinstance(value, x509.AuthorityKeyIdentifier):
                        aci = '✗'
                        if value.authority_cert_issuer:
                            aci = format_general_names(value.authority_cert_issuer)

                        this_cert_values['aki'] = [
                            critical,
                            bytes_to_hex(value.key_identifier),
                            aci,
                            value.authority_cert_serial_number if value.authority_cert_serial_number else '✗',
                        ]
                    elif isinstance(value, x509.BasicConstraints):
                        this_cert_values['basicconstraints'] = [
                            critical,
                            value.ca,
                            value.path_length if value.path_length is not None else 'None',
                        ]
                    elif isinstance(value, x509.SubjectAlternativeName):
                        continue  # not interesting here
                    else:
                        warn('Unknown extension: %s' % ext.oid._name)

            for key, row in this_cert_values.items():
                cert_values[key].append([cert_name] + row)

        for name, values in cert_values.items():
            filename = os.path.join(out_base, '%s_%s.rst' % (prefix, name))
            table = tabulate(values, headers='firstrow', tablefmt='rst')

            with open(filename, 'w') as stream:
                stream.write(table)

    ######################
    # Generate Cert data #
    ######################
    cert_dir = os.path.join(docs_base, '_files', 'cert')
    ca_dir = os.path.join(docs_base, '_files', 'ca')
    certs = {
        'jabberat.pem': {
            'name': 'Let\'s Encrypt X3',
            'last': '2019-04-19',
        },
        'derstandardat.pem': {
            'name': 'Go Daddy G2 Intermediate',
            'last': '2019-04-19',
        },
        'googlecom.pem': {
            'name': 'Google G3',
            'last': '2019-04-19',
        },
        'idertl.pem': {
            'name': 'Let\'s Encrypt X1',
            'last': '2016-04-22',
        }
    }
    cas = {
        'dst_root_x3.pem': {
            'name': 'DST X3',
            'last': '2019-04-19',
            'info': 'Root CA',
        },
        'godaddy_g2_root.pem': {
            'name': 'Go Daddy G2',
            'last': '2019-04-19',
            'info': 'Root CA',
        },
        'godaddy_g2_intermediate.pem': {
            'name': 'Go Daddy G2 Intermediate',
            'last': '2019-04-19',
            'info': 'Signed by Go Daddy G2',
        },
        'letsencrypt_x1.pem': {
            'name': 'Let\'s Encrypt X1',
            'last': '2016-04-22',
            'info': 'Signed by ???',
        },
        'letsencrypt_x3.pem': {
            'name': 'Let\'s Encrypt X3',
            'last': '2019-04-19',
            'info': 'Signed by DST X3',
        },
        'google_g3.pem': {
            'name': 'Google G3',
            'last': '2019-04-19',
            'info': 'Signed by GlobalSign R2',
        },
        'globalsign_r2_root.pem': {
            'name': 'GlobalSign R2',
            'last': '2019-04-19',
            'info': 'Root CA',
        },
        'startssl_root.pem': {
            'name': 'StartSSL',
            'last': '2016-04-22',
            'info': 'Root CA',
        },
        'startssl_class2.pem': {
            'name': 'StartSSL class 2',
            'last': '2016-04-22',
            'info': 'Signed by StartSSL',
        },
        'startssl_class3.pem': {
            'name': 'StartSSL class 2',
            'last': '2016-04-22',
            'info': 'Signed by StartSSL',
        },
    }

    _update_cert_data('cert', cert_dir, certs, 'Certificate')
    _update_cert_data('ca', ca_dir, cas, 'CA')

    #####################
    # Generate CRL data #
    #####################
    crls = {
        'gdig2s1-1015.crl': {
            'info': 'CRL in Go Daddy G2 end user certificates',
            'last': '2019-04-19',
            'name': 'Go Daddy G2/user',
            'url': 'http://crl.godaddy.com/gdig2s1-1015.crl',
        },
        'gdroot-g2.crl': {
            'info': 'CRL in Go Daddy G2 intermediate CA',
            'last': '2019-04-19',
            'name': 'Go Daddy G2/ca',
            'url': 'http://crl.godaddy.com/gdroot-g2.crl',
        },
        'DSTROOTCAX3CRL.crl': {
            'info': 'CRL in Let\'s Encrypt X3',
            'last': '2019-04-19',
            'name': "Let's Encrypt Authority X3/ca",
            'url': 'http://crl.identrust.com/DSTROOTCAX3CRL.crl',
        },
        'root-r2.crl': {
            'info': 'CRL in GlobalSign R2',
            'last': '2019-04-19',
            'name': 'GlobalSign R2/ca',
            'url': 'http://crl.globalsign.net/root-r2.crl',
        },
        'gsr2.crl': {
            'info': 'CRL in Google G3 CA',
            'last': '2019-04-19',
            'name': 'Google G3/ca',
            'url': 'http://crl.pki.goog/gsr2/gsr2.crl',
        },
        'GTSGIAG3.crl': {
            'info': 'CRL in Google G3 end user certificates',
            'last': '2019-04-19',
            'name': 'Google G3/user',
            'url': 'http://crl.pki.goog/GTSGIAG3.crl',
        },
    }

    crl_dir = os.path.join(docs_base, '_files', 'crl')
    crl_values = {
        # meta data
        'crl_info': [('CRL', 'Source', 'Last accessed', 'Info')],
        'crl_issuer': [('CRL', 'Issuer Name')],
        'crl_data': [('CRL', 'Update freq.', 'hash')],

        # extensions
        'crl_aki': [('CRL', 'key_identifier', 'cert_issuer', 'cert_serial')],
        'crl_crlnumber': [('CRL', 'number')],
        'crl_idp': [('CRL', 'full name', 'relative name', 'only attr certs', 'only ca certs',
                     'only user certs', 'reasons', 'indirect CRL', ), ]
    }

    for filename in sorted(os.listdir(crl_dir), key=lambda f: crls.get(f, {}).get('name', '')):
        if filename not in crls:
            warn('Unknown CRL: %s' % filename)
            continue

        crl_name = crls[filename]['name']

        # set empty string as default value
        not_present = ['']
        this_crl_values = {}
        for key, headers in crl_values.items():
            this_crl_values[key] = not_present * (len(crl_values[key][0]) - 1)

        with open(os.path.join(crl_dir, filename), 'rb') as stream:
            crl = x509.load_der_x509_crl(stream.read(), backend=default_backend())

            # add info
            this_crl_values['crl_info'] = (
                ':download:`%s </_files/crl/%s>` (`URL <%s>`__)' % (filename, filename,
                                                                    crls[filename]['url']),
                crls[filename]['last'],
                crls[filename]['info'],
            )

            # add data row
            this_crl_values['crl_data'] = (
                crl.next_update - crl.last_update,
                crl.signature_hash_algorithm.name,
            )
            this_crl_values['crl_issuer'] = (
                format_name(crl.issuer),
            )

            # add extension values
            for ext in crl.extensions:
                value = ext.value

                if isinstance(value, x509.CRLNumber):
                    this_crl_values['crl_crlnumber'] = (ext.value.crl_number, )
                elif isinstance(value, x509.IssuingDistributionPoint):
                    full_name = rel_name = reasons = '✗'
                    if value.full_name:
                        full_name = format_general_names(value.full_name)
                    if value.relative_name:
                        rel_name = format_name(value.relative_name)
                    if value.only_some_reasons:
                        reasons = ', '.join([f.name for f in value.only_some_reasons])

                    this_crl_values['crl_idp'] = (
                        full_name,
                        rel_name,
                        '✓' if value.only_contains_attribute_certs else '✗',
                        '✓' if value.only_contains_ca_certs else '✗',
                        '✓' if value.only_contains_user_certs else '✗',
                        reasons,
                        '✓' if value.indirect_crl else '✗',
                    )
                elif isinstance(value, x509.AuthorityKeyIdentifier):
                    aci = '✗'
                    if value.authority_cert_issuer:
                        aci = format_general_names(value.authority_cert_issuer)

                    this_crl_values['crl_aki'] = (
                        bytes_to_hex(value.key_identifier),
                        aci,
                        value.authority_cert_serial_number if value.authority_cert_serial_number else '✗',
                    )
                else:
                    warn('Unknown extension: %s' % ext.oid._name)

        for key, row in this_crl_values.items():
            crl_values[key].append([crl_name] + list(row))

    for name, values in crl_values.items():
        filename = os.path.join(out_base, '%s.rst' % name)
        table = tabulate(values, headers='firstrow', tablefmt='rst')

        with open(filename, 'w') as stream:
            stream.write(table)
else:
    parser.print_help()
