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
import json
import os
import shutil
import subprocess
import sys
import warnings

import packaging.version
import six

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

fix_parser = commands.add_parser('recreate-fixtures', help="Recreate test fixtures")

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

    from django_ca.utils import bytes_to_hex
    from django_ca.utils import format_general_name
    from django_ca.utils import format_general_names
    from django_ca.utils import format_name

    docs_base = os.path.join(_rootdir, 'docs', 'source')
    out_base = os.path.join(docs_base, 'generated')
    if not os.path.exists(out_base):
        os.makedirs(out_base)

    def _update_cert_data(prefix, cert_dir, certs, name_header):
        cert_values = {
            'subject': [(name_header, 'Subject', )],
            'issuer': [(name_header, 'Issuer', )],

            'aia': [(name_header, 'Critical', 'Values')],
            'aki': [(name_header, 'Critical', 'Key identifier', 'Issuer', 'Serial')],
            'basicconstraints': [(name_header, 'Critical', 'CA', 'Path length')],
            'eku': [(name_header, 'Critical', 'Usages')],
            'key_usage': [[name_header, 'Critical', 'digital_signature', 'content_commitment',
                           'key_encipherment', 'data_encipherment', 'key_agreement', 'key_cert_sign',
                           'crl_sign', 'encipher_only', 'decipher_only', ]],
            'ian': [(name_header, 'Critical', 'Names')],
            'ski': [(name_header, 'Critical', 'Digest')],
            'certificatepolicies': [(name_header, 'Critical', 'Policies')],
            'crldp': [(name_header, 'Critical', 'Names', 'RDNs', 'Issuer', 'Reasons')],
            'sct': [(name_header, 'Critical', 'Value')],
            'nc': [(name_header, 'Critical', 'Permitted', 'Excluded')],
        }

        for filename in sorted(os.listdir(cert_dir), key=lambda f: certs.get(f, {}).get('name', '')):
            if filename not in certs:
                warn('Unknown %s: %s' % (prefix, filename))
                continue
            print('Parsing %s (%s)...' % (filename, prefix))

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

                    if isinstance(value, x509.AuthorityInformationAccess):
                        this_cert_values['aia'] = [
                            critical, '\n'.join(
                                ['* %s: %s' % (v.access_method._name, format_general_name(v.access_location))
                                 for v in value])
                        ]
                    elif isinstance(value, x509.AuthorityKeyIdentifier):
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
                    elif isinstance(value, x509.CRLDistributionPoints):
                        this_cert_values['crldp'] = []
                        for dp in value:
                            full_name = '* '.join(
                                [format_general_name(name) for name in dp.full_name]
                            ) if dp.full_name else '✗'
                            issuer = '* '.join(
                                [format_general_name(name) for name in dp.crl_issuer]
                            ) if dp.crl_issuer else '✗'
                            reasons = ', '.join([r.name for r in dp.reasons]) if dp.reasons else '✗'
                            this_cert_values['crldp'].append([
                                critical,
                                full_name,
                                format_name(dp.relative_name) if dp.relative_name else '✗',
                                issuer, reasons,
                            ])
                    elif isinstance(value, x509.CertificatePolicies):
                        policies = []

                        def ref_as_str(r):
                            numbers = [str(n) for n in r.notice_numbers]
                            return '%s: %s' % (r.organization, ', '.join(numbers))

                        def policy_as_str(p):
                            if isinstance(p, six.string_types):
                                return p
                            elif p.explicit_text is None and p.notice_reference is None:
                                return 'Empty UserNotice'
                            elif p.notice_reference is None:
                                return 'User Notice: %s' % p.explicit_text
                            elif p.explicit_text is None:
                                return 'User Notice: %s' % (ref_as_str(p.notice_reference))
                            else:
                                return 'User Notice: %s: %s' % (ref_as_str(p.notice_reference),
                                                                p.explicit_text)

                        for policy in value:
                            policy_name = policy.policy_identifier.dotted_string
                            if policy.policy_qualifiers is None:
                                policies.append('* %s' % policy_name)
                            elif len(policy.policy_qualifiers) == 1:
                                policies.append('* %s: %s' % (
                                    policy_name,
                                    policy_as_str(policy.policy_qualifiers[0])
                                ))
                            else:
                                qualifiers = '\n'.join(
                                    ['  * %s' % policy_as_str(p) for p in policy.policy_qualifiers]
                                )
                                policies.append('* %s:\n\n%s\n' % (policy_name, qualifiers))

                        this_cert_values['certificatepolicies'] = [critical, '\n'.join(policies)]
                    elif isinstance(value, x509.ExtendedKeyUsage):
                        this_cert_values['eku'] = [
                            critical,
                            ', '.join([u._name for u in value]),
                        ]
                    elif isinstance(value, x509.IssuerAlternativeName):
                        this_cert_values['ian'] = [
                            critical,
                            format_general_names(value),
                        ]
                    elif isinstance(value, x509.KeyUsage):
                        key_usages = []
                        for key in cert_values['key_usage'][0][2:]:
                            try:
                                key_usages.append('✓' if getattr(value, key) else '✗')
                            except ValueError:
                                key_usages.append('✗')

                        this_cert_values['key_usage'] = [
                            critical,
                        ] + key_usages
                    elif isinstance(value, x509.NameConstraints):
                        permitted = '\n'.join(
                            ['* %s' % format_general_name(n) for n in value.permitted_subtrees]
                        ) if value.permitted_subtrees else '✗'
                        excluded = '\n'.join(
                            ['* %s' % format_general_name(n) for n in value.excluded_subtrees]
                        ) if value.excluded_subtrees else '✗'
                        this_cert_values['nc'] = [critical, permitted, excluded]
                    elif isinstance(value, x509.PrecertificateSignedCertificateTimestamps):
                        this_cert_values['sct'] = [
                            critical,
                            '\n'.join(['* Type: %s, version: %s' % (e.entry_type.name, e.version.name)
                                       for e in value])
                        ]
                    elif isinstance(value, x509.SubjectKeyIdentifier):
                        this_cert_values['ski'] = [critical, bytes_to_hex(value.digest)]
                    elif isinstance(value, x509.SubjectAlternativeName):
                        continue  # not interesting here
                    elif ext.oid.dotted_string in ['2.16.840.1.113730.1.1', '2.16.840.1.113730.1.13']:
                        # These are some OIDs identified by OpenSSL cli as "Netscape Cert Type" and
                        # "Netscape Comment". They only occur in the old, discontinued StartSSL root
                        # certificate.
                        continue
                    else:
                        warn('Unknown extension: %s' % ext.oid._name)

            for key, row in this_cert_values.items():
                if isinstance(row[0], list):
                    cert_values[key].append([cert_name] + row[0])
                    for mrow in row[1:]:
                        cert_values[key].append(['', ''] + mrow[1:])
                else:
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
        },
        'rapidssl_g3.pem': {
            'name': 'RapidSSL G3',
            'last': '2016-04-23',
        },
        'comodo_ev.pem': {
            'name': 'Comodo EV',
            'last': '2019-04-21',
        },
        'comodo_dv.pem': {
            'name': 'Comodo DV',
            'last': '2016-04-23',
        },
        'startssl_class2.pem': {
            'name': 'StartSSL class 2',
            'last': '2016-04-22',
        },
        'startssl_class3.pem': {
            'name': 'StartSSL class 3',
            'last': '2016-04-22',
        },
        'globalsign_dv.pem': {
            'name': 'GlobalSign DV',
            'last': '2016-04-23',
        },
        'digicert_ha_intermediate.pem': {
            'name': 'DigiCert HA Intermediate',
            'last': '2019-04-21',
        },
        'trustid_server_a52.pem': {
            'name': 'TrustID Server A52',
            'last': '2019-04-21',
        },
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
        'geotrust.pem': {
            'name': 'GeoTrust',
            'last': '2016-04-23',
            'info': 'Root CA',
        },
        'rapidssl_g3.pem': {
            'name': 'RapidSSL G3',
            'last': '2016-04-23',
            'info': 'Signed by GeoTrust',
        },
        'comodo.pem': {
            'name': 'Comodo',
            'last': '2019-04-21',
            'info': 'Root CA',
        },
        'comodo_ev.pem': {
            'name': 'Comodo EV',
            'last': '2019-04-21',
            'info': 'Signed by Comodo',
        },
        'comodo_dv.pem': {
            'name': 'Comodo DV',
            'last': '2016-04-23',
            'info': 'Signed by Comodo',
        },
        'globalsign.pem': {
            'name': 'GlobalSign',
            'last': '2016-04-23',
            'info': 'Root CA',
        },
        'globalsign_dv.pem': {
            'name': 'GlobalSign DV',
            'last': '2016-04-23',
            'info': 'Signed by GlobalSign',
        },
        'digicert_ev_root.pem': {
            'name': 'DigiCert EV Root',
            'last': '2019-04-21',
            'info': 'Root CA',
        },
        'digicert_ha_intermediate.pem': {
            'name': 'DigiCert HA Intermediate',
            'last': '2019-04-21',
            'info': 'Signed by DigiCert EV Root',
        },
        'identrust_root_1.pem': {
            'name': 'IdenTrust',
            'last': '2019-04-21',
            'info': 'Root CA',
        },
        'trustid_server_a52.pem': {
            'name': 'TrustID Server A52',
            'last': '2019-04-21',
            'info': 'Signed by IdenTrust',
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
        'comodo_ev_user.pem': {
            'info': 'CRL in %s end user certificates' % certs['comodo_ev.pem']['name'],
            'last': '2019-04-21',
            'name': '%s/user' % cas['comodo_ev.pem']['name'],
            'url': 'http://crl.comodoca.com/COMODORSAExtendedValidationSecureServerCA.crl',
        },
        'digicert_ha_intermediate.crl': {
            'info': 'CRL in %s' % cas['digicert_ha_intermediate.pem']['name'],
            'last': '2019-04-21',
            'name': '%s/ca' % cas['digicert_ha_intermediate.pem']['name'],
            'url': 'http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl',
        },
        'digicert_ha_intermediate_user.crl': {
            'info': 'CRL %s end user certificates' % cas['digicert_ha_intermediate.pem']['name'],
            'last': '2019-04-21',
            'name': '%s/user' % certs['digicert_ha_intermediate.pem']['name'],
            'url': 'http://crl3.digicert.com/sha2-ha-server-g6.crl',
        },
        'trustid_server_a52_ca.crl': {
            'info': 'CRL in %s' % cas['trustid_server_a52.pem']['name'],
            'last': '2019-04-21',
            'name': '%s/ca' % cas['trustid_server_a52.pem']['name'],
            'url': 'http://validation.identrust.com/crl/commercialrootca1.crl',
        },
        'trustid_server_a52_user.crl': {
            'info': 'CRL %s end user certificates' % cas['trustid_server_a52.pem']['name'],
            'last': '2019-04-21',
            'name': '%s/user' % certs['trustid_server_a52.pem']['name'],
            'url': 'http://validation.identrust.com/crl/trustidcaa52.crl',
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
elif args.command == 'recreate-fixtures':
    setup_django('ca.test_settings')

    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.serialization import NoEncryption
    from cryptography.hazmat.primitives.serialization import PrivateFormat

    from django.conf import settings
    from django.core.management import call_command as manage
    from django.urls import reverse
    manage('migrate', verbosity=0)

    from django_ca.models import CertificateAuthority
    from django_ca.tests.base import override_tmpcadir
    from django_ca.utils import ca_storage
    from django_ca.utils import bytes_to_hex

    def write_cert(cert, data, password=None):
        key_dest = os.path.join(settings.FIXTURES_DIR, data['key'])
        pub_dest = os.path.join(settings.FIXTURES_DIR, data['pub'])
        key_der_dest = os.path.join(settings.FIXTURES_DIR, data['key-der'])
        pub_der_dest = os.path.join(settings.FIXTURES_DIR, data['pub-der'])

        # write files to dest
        shutil.copy(ca_storage.path(cert.private_key_path), key_dest)
        with open(pub_dest, 'w') as stream:
            stream.write(cert.pub)

        if password is None:
            encryption = NoEncryption()
        else:
            encryption = BestAvailableEncryption(password)

        key_der = cert.key(password=password).private_bytes(encoding=Encoding.DER, format=PrivateFormat.PKCS8,
                                                            encryption_algorithm=encryption)
        with open(key_der_dest, 'wb') as stream:
            stream.write(key_der)
        with open(pub_der_dest, 'wb') as stream:
            stream.write(cert.dump_certificate(Encoding.DER))

        data['serial'] = cert.serial
        data['hpkp'] = cert.hpkp_pin
        data['authority_key_identifier'] = bytes_to_hex(cert.authority_key_identifier.value)
        data['subject_key_identifier'] = bytes_to_hex(cert.subject_key_identifier.value)
        data['valid_from'] = cert.x509.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
        data['valid_until'] = cert.x509.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')

        ku = cert.key_usage
        if ku is not None:
            data['key_usage'] = ku.serialize()

        aia = cert.authority_information_access
        if aia is not None:
            data['authority_information_access'] = aia.serialize()

    child_pathlen = 0
    ecc_pathlen = 1
    pwd_pathlen = 2
    dsa_pathlen = 3
    testserver = 'http://testserver'

    data = {
        'root': {
            'name': 'root',
            'password': None,
            'subject': '/C=AT/ST=Vienna/CN=ca.example.com',
            'pathlen': None,

            'basic_constraints': 'critical,CA:TRUE',
            'key_usage': 'critical,cRLSign,keyCertSign',
        },
        'child': {
            'name': 'child',
            'password': None,
            'subject': '/C=AT/ST=Vienna/CN=child.ca.example.org',

            'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % child_pathlen,
            'pathlen': child_pathlen,
            'name_constraints': [['DNS:.org'], ['DNS:.net']],
        },
        'ecc': {
            'name': 'ecc',
            'password': None,
            'subject': '/C=AT/ST=Vienna/CN=ecc.ca.example.org',

            'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % ecc_pathlen,
            'pathlen': ecc_pathlen,
        },
        'dsa': {
            'name': 'dsa',
            'password': None,
            'subject': '/C=AT/ST=Vienna/CN=dsa.ca.example.org',

            'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % dsa_pathlen,
            'pathlen': dsa_pathlen,
        },
        'pwd': {
            'name': 'pwd',
            'password': 'testpassword',
            'subject': '/C=AT/ST=Vienna/CN=pwd.ca.example.org',

            'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % pwd_pathlen,
            'pathlen': pwd_pathlen,
        },
    }

    data['root']['issuer'] = data['root']['subject']
    data['root']['issuer_url'] = '%s/%s.der' % (testserver, data['root']['name'])
    data['root']['ocsp_url'] = '%s/ocsp/%s/' % (testserver, data['root']['name'])
    data['child']['issuer'] = data['root']['subject']
    data['child']['crl'] = '%s/%s.crl' % (testserver, data['root']['name'])

    for cert, cert_values in data.items():
        cert_values['key'] = '%s.key' % cert_values['name']
        cert_values['pub'] = '%s.pem' % cert_values['name']
        cert_values['key-der'] = '%s-key.der' % cert_values['name']
        cert_values['pub-der'] = '%s-pub.der' % cert_values['name']

    with override_tmpcadir():
        root = CertificateAuthority.objects.init(
            name=data['root']['name'], subject=data['root']['subject'], key_size=1024,
        )
        root.crl_url = '%s%s' % (testserver, reverse('django_ca:crl', kwargs={'serial': root.serial}))
        root_ca_crl = '%s%s' % (testserver, reverse('django_ca:ca-crl', kwargs={'serial': root.serial}))
        root.save()
        write_cert(root, data['root'])

        child = CertificateAuthority.objects.init(
            name=data['child']['name'], subject=data['child']['subject'], parent=root, key_size=1024,
            pathlen=child_pathlen, ca_crl_url=root_ca_crl, ca_issuer_url=data['root']['issuer_url'],
            ca_ocsp_url=data['root']['ocsp_url']
        )
        data['child']['crl'] = root_ca_crl
        write_cert(child, data['child'])

        dsa = CertificateAuthority.objects.init(
            name=data['dsa']['name'], subject=data['dsa']['subject'], key_size=1024,
            pathlen=dsa_pathlen, key_type='DSA', algorithm='SHA1',
        )
        write_cert(dsa, data['dsa'])

        ecc = CertificateAuthority.objects.init(
            name=data['ecc']['name'], subject=data['ecc']['subject'], key_size=1024, key_type='ECC',
            pathlen=ecc_pathlen
        )
        write_cert(ecc, data['ecc'])

        pwd_password = data['pwd']['password'].encode('utf-8')
        pwd = CertificateAuthority.objects.init(
            name=data['pwd']['name'], subject=data['pwd']['subject'], key_size=1024, password=pwd_password,
            pathlen=pwd_pathlen
        )
        write_cert(pwd, data['pwd'], password=pwd_password)

        # add parent/child relationships
        data['root']['children'] = [
            [data['child']['name'], data['child']['serial']],
        ]
        data['child']['parent'] = [data['root']['name'], data['root']['serial']]

    fixture_data = {
        'certs': data,
    }

    with open(os.path.join(settings.FIXTURES_DIR, 'cert-data.json'), 'w') as stream:
        json.dump(fixture_data, stream, indent=4)
else:
    parser.print_help()
