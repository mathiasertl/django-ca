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
import subprocess
import sys
import traceback
import warnings

import packaging.version
import six
from termcolor import colored

import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import django
from django.core.exceptions import ImproperlyConfigured

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
cov_parser = commands.add_parser('coverage', parents=[suites_parser])
cov_parser.add_argument('--fail-under', type=int, default=100, metavar='[0-100]',
                        help='Fail if coverage is below given percentage (default: %(default)s%%).')

demo_parser = commands.add_parser('init-demo', help="Initialize the demo data.")

data_parser = commands.add_parser('update-ca-data', help="Update tables for ca_examples.rst in docs.")

args = parser.parse_args()

_rootdir = os.path.dirname(os.path.realpath(__file__))


def warn(msg, **kwargs):
    print(colored(msg, 'yellow'), **kwargs)


def ok(msg=' OK.', **kwargs):
    print(colored(msg, 'green'), **kwargs)


def bold(msg):
    return colored(msg, attrs=['bold'])


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

    suites = ['django_ca.tests.%s' % s.strip('.') for s in suites]

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
    if not default_backend()._lib.CRYPTOGRAPHY_OPENSSL_110F_OR_GREATER:
        cov.exclude(r'pragma:\s*only SCT')

    # exclude django-version specific code
    django_versions = [(1, 11), (2, 1), (2, 2), (2, 3), (2, 4)]

    for version in django_versions:
        version_str = '.'.join([str(v) for v in version])
        exclude_versions(cov, 'django', django.VERSION[:2], version, version_str)

    # exclude cryptography-version specific code
    this_version = packaging.version.parse(cryptography.__version__).release[:2]
    cryptography_versions = [(2, 3), (2, 4), (2, 5), (2, 6), (2, 7), (2, 8), (2, 9)]
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

    print('flake8 ca/ setup.py dev.py recreate-fixtures.py')
    status = subprocess.call(['flake8', 'ca/', 'setup.py', 'dev.py', 'recreate-fixtures.py'])
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
    try:
        setup_django('ca.settings')
    except ImproperlyConfigured:
        # Cannot import settings, probably because localsettings.py wasn't created.
        traceback.print_exc()
        localsettings = os.path.join(_rootdir, 'ca', 'ca', 'localsettings.py')
        print("""
Could not configure settings! Have you created localsettings.py?

Please create %(localsettings)s from %(example)s and try again.""" % {
            'localsettings': localsettings,
            'example': '%s.example' % localsettings,
        })
        sys.exit(1)

    from django.contrib.auth import get_user_model
    from django.core.files.base import ContentFile
    from django.core.management import call_command as manage
    from django.urls import reverse

    from django_ca import ca_settings
    from django_ca.models import Certificate
    from django_ca.models import CertificateAuthority
    from django_ca.utils import ca_storage

    User = get_user_model()

    print('Creating database...', end='')
    manage('migrate', verbosity=0)
    ok()

    if not os.path.exists(ca_settings.CA_DIR):
        os.makedirs(ca_settings.CA_DIR)

    print('Creating fixture data...', end='')
    subprocess.call(['./recreate-fixtures.py', '--no-delay', '--ca-validity=3650', '--cert-validity=732',
                     '--dest=%s' % ca_settings.CA_DIR])
    with open(os.path.join(ca_settings.CA_DIR, 'cert-data.json')) as stream:
        fixture_data = json.load(stream)
    ok()

    print('Saving fixture data to database.', end='')
    loaded_cas = {}
    certs = fixture_data['certs']
    for cert_name, cert_data in certs.items():
        if cert_data['type'] == 'ca':
            if not cert_data['key_filename']:
                continue  # CA without private key (e.g. real-world CA)

            name = cert_data['name']
            path = '%s.key' % name

            with open(os.path.join(ca_settings.CA_DIR, cert_data['key_filename']), 'rb') as stream:
                pkey = stream.read()

            c = CertificateAuthority(name=name, private_key_path=path)
            loaded_cas[c.name] = c
        else:
            if cert_data['cat'] != 'generated':
                continue  # Imported cert

            c = Certificate(ca=loaded_cas[cert_data['ca']])

        with open(os.path.join(ca_settings.CA_DIR, cert_data['pub_filename']), 'rb') as stream:
            pem = stream.read()
        c.x509 = x509.load_pem_x509_certificate(pem, default_backend())

        c.save()

        if cert_data['type'] == 'ca':
            password = cert_data.get('password')
            if password is not None:
                password = password.encode('utf-8')
            c.generate_ocsp_key(password=password)

    # create admin user for login
    User.objects.create_superuser('user', 'user@example.com', 'nopass')

    ok()

    # create a chain file for the child
    chain = loaded_cas['child'].pub + loaded_cas['root'].pub
    chain_path = ca_storage.path(ca_storage.save('data/child-chain.pem', ContentFile(chain)))

    base_url = 'http://localhost:8000/'
    cwd = os.getcwd()
    rel = lambda p: os.path.relpath(p, cwd)  # NOQA
    root_ca_path = ca_storage.path(certs['root']['pub_filename'])
    child_ca_path = ca_storage.path(certs['child']['pub_filename'])

    root_cert_path = ca_storage.path(certs['root-cert']['pub_filename'])
    child_cert_path = ca_storage.path(certs['child-cert']['pub_filename'])

    ocsp_url = '%s%s' % (base_url.rstrip('/'),
                         reverse('django_ca:ocsp-cert-post', kwargs={'serial': certs['child']['serial']}))

    print("")
    print('* All certificates are in %s.' % bold(ca_settings.CA_DIR))
    ok('* Start webserver with the admin interface:')
    print('  * Run "%s"' % bold('python ca/manage.py runserver'))
    print('  * Visit %s' % bold('%sadmin/' % base_url))
    print('  * User/Password: %s / %s' % (bold('user'), bold('nopass')))
    ok('* Create CRLs with:')
    print('  * %s' % bold('python ca/manage.py dump_crl -f PEM --ca %s > root.crl' %
                          loaded_cas['root'].serial[:11]))
    print('  * %s' % bold('python ca/manage.py dump_crl -f PEM --ca %s > child.crl' %
                          loaded_cas['child'].serial[:11]))
    ok('* Verify with CRL:')
    print('  * %s' % bold('openssl verify -CAfile %s -CRLfile root.crl -crl_check %s' % (
                          rel(root_ca_path), rel(root_cert_path))))
    print('  * %s' % bold('openssl verify -CAfile %s -crl_download -crl_check %s' % (
                          rel(root_ca_path), rel(root_cert_path))))
    ok('* Verify certificate with OCSP:')
    print('    %s' % bold('openssl ocsp -CAfile %s -issuer %s -cert %s -url %s -resp_text' % (
        rel(root_ca_path), rel(child_ca_path), rel(child_cert_path), ocsp_url)))

elif args.command == 'update-ca-data':
    setup_django('ca.settings')

    from tabulate import tabulate

    from django_ca.utils import bytes_to_hex
    from django_ca.utils import format_general_name
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
            'unknown': [(name_header, 'Extensions')],
        }
        exclude_empty_lines = {'unknown', }

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
                            aci = format_general_name(value.authority_cert_issuer)

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
                            '* '.join([format_general_name(v) for v in value]),
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
                    else:
                        # These are some OIDs identified by OpenSSL cli as "Netscape Cert Type" and
                        # "Netscape Comment". They only occur in the old, discontinued StartSSL root
                        # certificate.
                        if ext.oid.dotted_string == '2.16.840.1.113730.1.1':
                            name = 'Netscape Cert Type'
                        elif ext.oid.dotted_string == '2.16.840.1.113730.1.13':
                            name = "Netscape Comment"
                        else:
                            name = ext.oid._name

                        ext_str = '%s (Critical: %s, OID: %s)' % (name, ext.critical, ext.oid.dotted_string)
                        this_cert_values['unknown'].append(ext_str)

            this_cert_values['unknown'] = ['\n'.join(['* %s' % v for v in this_cert_values['unknown'][1:]])]

            for key, row in this_cert_values.items():
                if isinstance(row[0], list):
                    cert_values[key].append([cert_name] + row[0])
                    for mrow in row[1:]:
                        cert_values[key].append(['', ''] + mrow[1:])
                else:
                    cert_values[key].append([cert_name] + row)

        for name, values in cert_values.items():
            filename = os.path.join(out_base, '%s_%s.rst' % (prefix, name))

            if name in exclude_empty_lines:
                values = [v for v in values if ''.join(v[1:])]

            if values:
                table = tabulate(values, headers='firstrow', tablefmt='rst')
            else:
                table = ''

            with open(filename, 'w') as stream:
                stream.write(table)

    ######################
    # Generate Cert data #
    ######################
    cert_dir = os.path.join(docs_base, '_files', 'cert')
    ca_dir = os.path.join(docs_base, '_files', 'ca')
    certs = {
        'digicert_sha2.pem': {  # derstandard.at
            'name': 'DigiCert Secure Server',
            'last': '2019-07-06',
        },
        'letsencrypt_x3.pem': {  # jabber.at
            'name': 'Let\'s Encrypt X3',
            'last': '2019-07-06',
        },
        'godaddy_g2_intermediate.pem': {
            'name': 'Go Daddy G2 Intermediate',
            'last': '2019-04-19',
        },
        'google_g3.pem': {
            'name': 'Google G3',
            'last': '2019-04-19',
        },
        'letsencrypt_x1.pem': {
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
        'digicert_sha2.pem': {  # derstandard.at
            'name': 'DigiCert Secure Server',
            'last': '2019-07-06',
            'info': 'Signed by DigiCert Global Root',
        },
        'digicert_global_root.pem': {  # derstandard.at
            'name': 'DigiCert Global Root',
            'last': '2019-07-06',
        },
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
                        full_name = '* '.join([format_general_name(v) for v in value.full_name])
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
                        aci = '* '.join([format_general_name(v) for v in value.authority_cert_issuer])

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
