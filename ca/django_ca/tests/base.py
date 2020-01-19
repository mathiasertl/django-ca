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

import copy
import inspect
import json
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime
from datetime import timedelta
from io import StringIO
from unittest.mock import Mock
from unittest.mock import patch

from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import X509Store
from OpenSSL.crypto import X509StoreContext
from OpenSSL.crypto import load_certificate

import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.management import ManagementUtility
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import reverse

from pyvirtualdisplay import Display
from selenium.webdriver.firefox.webdriver import WebDriver
from selenium.webdriver.support.wait import WebDriverWait

from .. import ca_settings
from ..constants import ReasonFlags
from ..extensions import KEY_TO_EXTENSION
from ..extensions import Extension
from ..extensions import IterableExtension
from ..extensions import ListExtension
from ..models import Certificate
from ..models import CertificateAuthority
from ..signals import post_create_ca
from ..signals import post_issue_cert
from ..signals import post_revoke_cert
from ..subject import Subject
from ..utils import add_colons
from ..utils import ca_storage
from ..utils import x509_name

User = get_user_model()


def _load_key(data):
    basedir = data.get('basedir', settings.FIXTURES_DIR)
    path = os.path.join(basedir, data['key_filename'])

    with open(path, 'rb') as stream:
        raw = stream.read()

    parsed = serialization.load_pem_private_key(raw, password=data.get('password'), backend=default_backend())
    return {
        'pem': raw.decode('utf-8'),
        'parsed': parsed,
    }


def _load_csr(data):
    basedir = data.get('basedir', settings.FIXTURES_DIR)
    path = os.path.join(basedir, data['csr_filename'])

    with open(path, 'rb') as stream:
        raw = stream.read().strip()

    csr_data = {
        'pem': raw.decode('utf-8'),
        'parsed': x509.load_pem_x509_csr(raw, default_backend()),
    }

    csr_data['der'] = csr_data['parsed'].public_bytes(Encoding.DER)

    return csr_data


def _load_pub(data):
    basedir = data.get('basedir', settings.FIXTURES_DIR)
    path = os.path.join(basedir, data['pub_filename'])

    with open(path, 'rb') as stream:
        pem = stream.read().replace(b'\r\n', b'\n')

    pub_data = {
        'pem': pem.decode('utf-8'),
        'parsed': x509.load_pem_x509_certificate(pem, default_backend()),
    }

    if data.get('pub_der_filename'):
        der_path = os.path.join(basedir, data['pub_der_filename'])
        with open(der_path, 'rb') as stream:
            der = stream.read().replace(b'\r\n', b'\n')
        pub_data['der'] = der
        # Failes for alt-extensions since alternative AKI was added
        #pub_data['der_parsed'] = x509.load_der_x509_certificate(der, default_backend()),

    return pub_data


cryptography_version = tuple([int(t) for t in cryptography.__version__.split('.')[:2]])

with open(os.path.join(settings.FIXTURES_DIR, 'cert-data.json')) as stream:
    _fixture_data = json.load(stream)
certs = _fixture_data.get('certs')

# Update some data from contrib (data is not in cert-data.json, since we don't generate them)
certs['multiple_ous'] = {
    'name': 'multiple_ous',
    'cn': '',
    'key_filename': False,
    'csr_filename': False,
    'pub_filename': os.path.join('contrib', 'multiple_ous_and_no_ext.pem'),
    'cat': 'contrib',
    'type': 'cert',
    'valid_from': '1998-05-18 00:00:00',
    'valid_until': '2028-08-01 23:59:59',
    'ca': 'root',
    'serial': '7DD9FE07CFA81EB7107967FBA78934C6',
    'hpkp': 'AjyBzOjnxk+pQtPBUEhwfTXZu1uH9PVExb8bxWQ68vo=',
    'md5': 'A2:33:9B:4C:74:78:73:D4:6C:E7:C1:F3:8D:CB:5C:E9',
    'sha1': '85:37:1C:A6:E5:50:14:3D:CE:28:03:47:1B:DE:3A:09:E8:F8:77:0F',
    'sha256': '83:CE:3C:12:29:68:8A:59:3D:48:5F:81:97:3C:0F:91:95:43:1E:DA:37:CC:5E:36:43:0E:79:C7:A8:88:63:8B',  # NOQA
    'sha512': '86:20:07:9F:8B:06:80:43:44:98:F6:7A:A4:22:DE:7E:2B:33:10:9B:65:72:79:C4:EB:F3:F3:0F:66:C8:6E:89:1D:4C:6C:09:1C:83:45:D1:25:6C:F8:65:EB:9A:B9:50:8F:26:A8:85:AE:3A:E4:8A:58:60:48:65:BB:44:B6:CE',  # NOQA
}
certs['cloudflare_1'] = {
    'name': 'cloudflare_1',
    'cn': 'sni24142.cloudflaressl.com',
    'key_filename': False,
    'csr_filename': False,
    'pub_filename': os.path.join('contrib', 'cloudflare_1.pem'),
    'cat': 'contrib',
    'type': 'cert',
    'valid_from': '2018-07-18 00:00:00',
    'valid_until': '2019-01-24 23:59:59',
    'ca': 'root',
    'serial': '92529ABD85F0A6A4D6C53FD1C91011C1',
    'hpkp': 'bkunFfRSda4Yhz7UlMUaalgj0Gcus/9uGVp19Hceczg=',
    'md5': 'D6:76:03:E9:4F:3B:B0:F1:F7:E3:A1:40:80:8E:F0:4A',
    'sha1': '71:BD:B8:21:80:BD:86:E8:E5:F4:2B:6D:96:82:B2:EF:19:53:ED:D3',
    'sha256': '1D:8E:D5:41:E5:FF:19:70:6F:65:86:A9:A3:6F:DF:DE:F8:A0:07:22:92:71:9E:F1:CD:F8:28:37:39:02:E0:A1',  # NOQA
    'sha512': 'FF:03:1B:8F:11:E8:A7:FF:91:4F:B9:97:E9:97:BC:77:37:C1:A7:69:86:F3:7C:E3:BB:BB:DF:A6:4F:0E:3C:C0:7F:B5:BC:CC:BD:0A:D5:EF:5F:94:55:E9:FF:48:41:34:B8:11:54:57:DD:90:85:41:2E:71:70:5E:FA:BA:E6:EA',  # NOQA
    "authority_information_access": {
        "critical": False,
        "value": {
            "issuers": [
                "URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt"
            ],
            "ocsp": [
                "URI:http://ocsp.comodoca4.com"
            ],
        }
    },
    'authority_key_identifier': {
        'critical': False,
        'value': '40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96',
    },
    "basic_constraints": {
        'critical': True,
        'value': {'ca': False},
    },
    "crl_distribution_points": {
        "value": [
            {
                "full_name": [
                    'URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl',
                ],
            }
        ],
        "critical": False,
    },
    "extended_key_usage": {
        'critical': False,
        'value': ['serverAuth', 'clientAuth'],
    },
    "key_usage": {
        'critical': True,
        'value': ['digitalSignature'],
    },
    'precert_poison': {'critical': True},
    'subject_alternative_name': {'value': [
        'DNS:sni24142.cloudflaressl.com', 'DNS:*.animereborn.com', 'DNS:*.beglideas.ga', 'DNS:*.chroma.ink',
        'DNS:*.chuckscleanings.ga', 'DNS:*.clipvuigiaitris.ga', 'DNS:*.cmvsjns.ga', 'DNS:*.competegraphs.ga',
        'DNS:*.consoleprints.ga', 'DNS:*.copybreezes.ga', 'DNS:*.corphreyeds.ga', 'DNS:*.cyanigees.ga',
        'DNS:*.dadpbears.ga', 'DNS:*.dahuleworldwides.ga', 'DNS:*.dailyopeningss.ga', 'DNS:*.daleylexs.ga',
        'DNS:*.danajweinkles.ga', 'DNS:*.dancewthyogas.ga', 'DNS:*.darkmoosevpss.ga', 'DNS:*.daurat.com.ar',
        'DNS:*.deltaberg.com', 'DNS:*.drjahanobgyns.ga', 'DNS:*.drunkgirliess.ga', 'DNS:*.duhiepkys.ga',
        'DNS:*.dujuanjsqs.ga', 'DNS:*.dumbiseasys.ga', 'DNS:*.dumpsoftdrinkss.ga', 'DNS:*.dunhavenwoodss.ga',
        'DNS:*.durabiliteas.ga', 'DNS:*.duxmangroups.ga', 'DNS:*.dvpdrivewayss.ga', 'DNS:*.dwellwizes.ga',
        'DNS:*.dwwkouis.ga', 'DNS:*.entertastic.com', 'DNS:*.estudiogolber.com.ar', 'DNS:*.letsretro.team',
        'DNS:*.maccuish.org.uk', 'DNS:*.madamsquiggles.com', 'DNS:*.sftw.ninja', 'DNS:*.spangenberg.io',
        'DNS:*.timmutton.com.au', 'DNS:*.wyomingsexbook.com', 'DNS:*.ych.bid', 'DNS:animereborn.com',
        'DNS:beglideas.ga', 'DNS:chroma.ink', 'DNS:chuckscleanings.ga', 'DNS:clipvuigiaitris.ga',
        'DNS:cmvsjns.ga', 'DNS:competegraphs.ga', 'DNS:consoleprints.ga', 'DNS:copybreezes.ga',
        'DNS:corphreyeds.ga', 'DNS:cyanigees.ga', 'DNS:dadpbears.ga', 'DNS:dahuleworldwides.ga',
        'DNS:dailyopeningss.ga', 'DNS:daleylexs.ga', 'DNS:danajweinkles.ga', 'DNS:dancewthyogas.ga',
        'DNS:darkmoosevpss.ga', 'DNS:daurat.com.ar', 'DNS:deltaberg.com', 'DNS:drjahanobgyns.ga',
        'DNS:drunkgirliess.ga', 'DNS:duhiepkys.ga', 'DNS:dujuanjsqs.ga', 'DNS:dumbiseasys.ga',
        'DNS:dumpsoftdrinkss.ga', 'DNS:dunhavenwoodss.ga', 'DNS:durabiliteas.ga', 'DNS:duxmangroups.ga',
        'DNS:dvpdrivewayss.ga', 'DNS:dwellwizes.ga', 'DNS:dwwkouis.ga', 'DNS:entertastic.com',
        'DNS:estudiogolber.com.ar', 'DNS:letsretro.team', 'DNS:maccuish.org.uk', 'DNS:madamsquiggles.com',
        'DNS:sftw.ninja', 'DNS:spangenberg.io', 'DNS:timmutton.com.au', 'DNS:wyomingsexbook.com',
        'DNS:ych.bid',
    ]},
    'subject_key_identifier': {
        'critical': False,
        'value': '05:86:D8:B4:ED:A9:7E:23:EE:2E:E7:75:AA:3B:2C:06:08:2A:93:B2',
    },
    'policy_texts': [
        '''Policy Identifier: 1.3.6.1.4.1.6449.1.2.2.7
Policy Qualifiers:
* https://secure.comodo.com/CPS''',
        '''Policy Identifier: 2.23.140.1.2.1
No Policy Qualifiers''',
    ],
    'certificate_policies': {
        'value': [{
            'policy_identifier': '1.3.6.1.4.1.6449.1.2.2.7',
            'policy_qualifiers': ['https://secure.comodo.com/CPS'],
        }, {
            'policy_identifier': '2.23.140.1.2.1'},
        ],
        'critical': False,
    }
}

SPHINX_FIXTURES_DIR = os.path.join(os.path.dirname(settings.BASE_DIR), 'docs', 'source', '_files')
for cert_name, cert_data in certs.items():
    cert_data['serial_colons'] = add_colons(cert_data['serial'])
    if cert_data.get('password'):
        cert_data['password'] = cert_data['password'].encode('utf-8')
    if cert_data['cat'] == 'sphinx-contrib':
        cert_data['basedir'] = os.path.join(SPHINX_FIXTURES_DIR, cert_data['type'])

    if cert_data['type'] == 'ca':
        cert_data.setdefault('children', [])

    # Load data from files
    if cert_data['key_filename'] is not False:
        cert_data['key'] = _load_key(cert_data)
    if cert_data['csr_filename'] is not False:
        cert_data['csr'] = _load_csr(cert_data)
    cert_data['pub'] = _load_pub(cert_data)

    # parse some data from the dict
    cert_data['valid_from'] = datetime.strptime(cert_data['valid_from'], '%Y-%m-%d %H:%M:%S')
    cert_data['valid_until'] = datetime.strptime(cert_data['valid_until'], '%Y-%m-%d %H:%M:%S')
    cert_data['valid_from_short'] = cert_data['valid_from'].strftime('%Y-%m-%d %H:%M')
    cert_data['valid_until_short'] = cert_data['valid_until'].strftime('%Y-%m-%d %H:%M')

    cert_data['ocsp-serial'] = cert_data['serial'].replace(':', '')
    cert_data['ocsp-expires'] = cert_data['valid_until'].strftime('%y%m%d%H%M%SZ')

    # parse extensions
    for key, cls in KEY_TO_EXTENSION.items():
        if cert_data.get(key):
            cert_data['%s_serialized' % key] = cert_data[key]
            cert_data[key] = cls(cert_data[key])

# Calculate some fixted timestamps that we reuse throughout the tests
timestamps = {
    'base': datetime.strptime(_fixture_data['timestamp'], '%Y-%m-%d %H:%M:%S'),
}
timestamps['before_everything'] = datetime(1990, 1, 1)
timestamps['before_cas'] = timestamps['base'] - timedelta(days=1)
timestamps['before_child'] = timestamps['base'] + timedelta(days=1)
timestamps['after_child'] = timestamps['base'] + timedelta(days=4)
timestamps['ca_certs_valid'] = timestamps['base'] + timedelta(days=7)
timestamps['profile_certs_valid'] = timestamps['base'] + timedelta(days=12)
timestamps['everything_valid'] = timestamps['base'] + timedelta(days=60)
timestamps['cas_expired'] = timestamps['base'] + timedelta(days=731, seconds=3600)
timestamps['ca_certs_expiring'] = certs['root-cert']['valid_until'] - timedelta(days=3)
timestamps['ca_certs_expired'] = certs['root-cert']['valid_until'] + timedelta(seconds=3600)
timestamps['profile_certs_expired'] = certs['profile-server']['valid_until'] + timedelta(seconds=3600)
timestamps['everything_expired'] = timestamps['base'] + timedelta(days=365 * 20)
ocsp_data = _fixture_data['ocsp']


def dns(d):  # just a shortcut
    return x509.DNSName(d)


def uri(u):  # just a shortcut
    return x509.UniformResourceIdentifier(u)


def rdn(r):  # just a shortcut
    return x509.RelativeDistinguishedName([x509.NameAttribute(*t) for t in r])


@contextmanager
def mock_cadir(path):
    """Contextmanager to set the CA_DIR to a given path without actually creating it."""
    with override_settings(CA_DIR=path), \
            patch.object(ca_storage, 'location', path), \
            patch.object(ca_storage, '_location', path):
        yield


class override_tmpcadir(override_settings):
    """Sets the CA_DIR directory to a temporary directory.

    .. NOTE: This also takes any additional settings.
    """

    def __call__(self, test_func):
        if not inspect.isfunction(test_func):
            raise ValueError("Only functions can use override_tmpcadir()")
        return super(override_tmpcadir, self).__call__(test_func)

    def enable(self):
        self.options['CA_DIR'] = tempfile.mkdtemp()

        # copy CAs
        for filename in [v['key_filename'] for v in certs.values() if v['key_filename'] is not False]:
            shutil.copy(os.path.join(settings.FIXTURES_DIR, filename), self.options['CA_DIR'])

        # Copy OCSP public key (required for OCSP tests)
        shutil.copy(os.path.join(settings.FIXTURES_DIR, certs['profile-ocsp']['pub_filename']),
                    self.options['CA_DIR'])

        self.mock = patch.object(ca_storage, 'location', self.options['CA_DIR'])
        self.mock_ = patch.object(ca_storage, '_location', self.options['CA_DIR'])
        self.mock.start()
        self.mock_.start()

        super(override_tmpcadir, self).enable()

    def disable(self):
        super(override_tmpcadir, self).disable()
        self.mock.stop()
        self.mock_.stop()
        shutil.rmtree(self.options['CA_DIR'])


class DjangoCATestCaseMixin:
    """Base class for all testcases with some enhancements."""

    re_false_password = r'^(Bad decrypt\. Incorrect password\?|Could not deserialize key data\.)$'

    def setUp(self):
        super(DjangoCATestCaseMixin, self).setUp()
        self.cas = {}
        self.certs = {}

    def tearDown(self):
        super().tearDown()
        cache.clear()

    def tmpcadir(self, **kwargs):
        """Context manager to use a temporary CA dir."""
        return override_tmpcadir(**kwargs)

    def mock_cadir(self, path):
        return mock_cadir(path)

    def assertAuthorityKeyIdentifier(self, issuer, cert, critical=False):
        self.assertEqual(cert.authority_key_identifier.key_identifier, issuer.subject_key_identifier.value)

    def assertBasic(self, cert, algo='SHA256'):
        """Assert some basic key properties."""
        self.assertEqual(cert.version, x509.Version.v3)
        self.assertIsInstance(cert.public_key(), rsa.RSAPublicKey)
        self.assertIsInstance(cert.signature_hash_algorithm, getattr(hashes, algo.upper()))

    def assertCRL(self, crl, certs=None, signer=None, expires=86400, algorithm=None, encoding=Encoding.PEM,
                  idp=None, extensions=None, crl_number=0, skip_authority_key_identifier=False):
        certs = certs or []
        signer = signer or self.cas['child']
        algorithm = algorithm or ca_settings.CA_DIGEST_ALGORITHM
        extensions = extensions or []
        expires = datetime.utcnow() + timedelta(seconds=expires)

        if idp is not None:  # pragma: no branch
            extensions.append(idp)
        extensions.append(x509.Extension(
            value=x509.CRLNumber(crl_number=crl_number),
            critical=False, oid=ExtensionOID.CRL_NUMBER
        ))
        if not skip_authority_key_identifier:
            extensions.append(signer.authority_key_identifier.as_extension())

        if encoding == Encoding.PEM:
            crl = x509.load_pem_x509_crl(crl, default_backend())
        else:
            crl = x509.load_der_x509_crl(crl, default_backend())

        self.assertIsInstance(crl.signature_hash_algorithm, type(algorithm))
        self.assertTrue(crl.is_signature_valid(signer.x509.public_key()))
        self.assertEqual(crl.issuer, signer.x509.subject)
        self.assertEqual(crl.last_update, datetime.utcnow())
        self.assertEqual(crl.next_update, expires)
        self.assertCountEqual(list(crl.extensions), extensions)

        entries = {e.serial_number: e for e in crl}
        expected = {c.x509.serial_number: c for c in certs}
        self.assertCountEqual(entries, expected)
        for serial, entry in entries.items():
            self.assertEqual(entry.revocation_date, datetime.utcnow())
            self.assertEqual(list(entry.extensions), [])

    @contextmanager
    def assertCommandError(self, msg):
        """Context manager asserting that CommandError is raised.

        Parameters
        ----------

        msg : str
            The regex matching the exception message.
        """
        with self.assertRaisesRegex(CommandError, msg):
            yield

    def assertIssuer(self, issuer, cert):
        self.assertEqual(cert.issuer, issuer.subject)

    def assertMessages(self, response, expected):
        messages = [str(m) for m in list(get_messages(response.wsgi_request))]
        self.assertEqual(messages, expected)

    @contextmanager
    def assertMultipleWarnings(self, warnings, msg=None):  # pragma: no cover
        # not used in 1.16, but might still be useful
        arg = tuple([w['category'] for w in warnings if w.get('category')])
        with self.assertWarns(arg, msg=msg) as cm:
            yield cm

        self.assertEqual(len(warnings), len(cm.warnings))

        for data, msg in zip(warnings, cm.warnings):
            self.assertEqual(msg.category, data['category'])

            error = '"%s" does not match "%s"' % (msg.message, data['msg'])
            self.assertIsNotNone(re.match(data['msg'], str(msg.message)), error)

            if data.get('filename'):  # pragma: no cover - so far this is always None
                self.assertEqual(data['filename'], msg.filename)
            if data.get('lineno'):  # pragma: no cover - so far this is always None
                self.assertEqual(data['lineno'], msg.lineno)
            self.assertEqual(data.get('file'), msg.file)
            self.assertEqual(data.get('line'), msg.line)

            if hasattr(msg, 'source'):  # pragma: no branch, pragma: only py>=3.6, not present in py3.5
                self.assertEqual(data.get('source'), msg.source)

    def assertNotRevoked(self, cert):
        if isinstance(cert, CertificateAuthority):
            cert = CertificateAuthority.objects.get(serial=cert.serial)
        else:
            cert = Certificate.objects.get(serial=cert.serial)

        self.assertFalse(cert.revoked)
        self.assertEqual(cert.revoked_reason, '')

    def assertParserError(self, args, expected, **kwargs):
        """Assert that given args throw a parser error."""

        kwargs.setdefault('script', os.path.basename(sys.argv[0]))
        expected = expected.format(**kwargs)

        buf = StringIO()
        with self.assertRaises(SystemExit), patch('sys.stderr', buf):
            self.parser.parse_args(args)

        output = buf.getvalue()
        self.assertEqual(output, expected)
        return output

    def assertPostCreateCa(self, post, ca):
        post.assert_called_once_with(ca=ca, signal=post_create_ca, sender=CertificateAuthority)

    def assertPostIssueCert(self, post, cert):
        post.assert_called_once_with(cert=cert, signal=post_issue_cert, sender=Certificate)

    def assertPostRevoke(self, post, cert):
        post.assert_called_once_with(cert=cert, signal=post_revoke_cert, sender=Certificate)

    def assertPrivateKey(self, ca, password=None):
        key = ca.key(password)
        self.assertIsNotNone(key)
        self.assertTrue(key.key_size > 0)

    def assertRevoked(self, cert, reason=None):
        if isinstance(cert, CertificateAuthority):
            cert = CertificateAuthority.objects.get(serial=cert.serial)
        else:
            cert = Certificate.objects.get(serial=cert.serial)

        self.assertTrue(cert.revoked)

        if reason is None:
            self.assertEqual(cert.revoked_reason, ReasonFlags.unspecified.name)
        else:
            self.assertEqual(cert.revoked_reason, reason)

    def assertSerial(self, serial):
        """Assert that the serial matches a basic regex pattern."""
        self.assertIsNotNone(re.match('^[0-9A-F:]*$', serial), serial)

    @contextmanager
    def assertSignal(self, signal):
        handler = Mock()
        signal.connect(handler)
        yield handler
        signal.disconnect(handler)

    def assertSignature(self, chain, cert):
        # see: http://stackoverflow.com/questions/30700348
        store = X509Store()

        # set the time of the OpenSSL context - freezegun doesn't work, because timestamp comes from OpenSSL
        now = datetime.utcnow()
        store.set_time(now)

        for elem in chain:
            ca = load_certificate(FILETYPE_PEM, elem.dump_certificate())
            store.add_cert(ca)

            # Verify that the CA itself is valid
            store_ctx = X509StoreContext(store, ca)
            self.assertIsNone(store_ctx.verify_certificate())

        cert = load_certificate(FILETYPE_PEM, cert.dump_certificate())
        store_ctx = X509StoreContext(store, cert)
        self.assertIsNone(store_ctx.verify_certificate())

    def assertSubject(self, cert, expected):
        if not isinstance(expected, Subject):
            expected = Subject(expected)
        self.assertEqual(Subject([(s.oid, s.value) for s in cert.subject]), expected)

    @contextmanager
    def assertValidationError(self, errors):
        with self.assertRaises(ValidationError) as cm:
            yield
        self.assertEqual(cm.exception.message_dict, errors)

    def cmd(self, *args, **kwargs):
        """Call to a manage.py command using call_command."""
        kwargs.setdefault('stdout', StringIO())
        kwargs.setdefault('stderr', StringIO())
        stdin = kwargs.pop('stdin', StringIO())

        with patch('sys.stdin', stdin):
            call_command(*args, **kwargs)
        return kwargs['stdout'].getvalue(), kwargs['stderr'].getvalue()

    def cmd_e2e(self, cmd, stdin=None, stdout=None, stderr=None):
        """Call a management command the way manage.py does.

        Unlike call_command, this method also tests the argparse configuration of the called command.
        """
        stdout = stdout or StringIO()
        stderr = stderr or StringIO()
        if stdin is None:
            stdin = StringIO()

        with patch('sys.stdin', stdin), patch('sys.stdout', stdout), patch('sys.stderr', stderr):
            util = ManagementUtility(['manage.py', ] + list(cmd))
            util.execute()

        return stdout.getvalue(), stderr.getvalue()

    @property
    def crl_profiles(self):
        profiles = copy.deepcopy(ca_settings.CA_CRL_PROFILES)
        for name, config in profiles.items():
            config.setdefault('OVERRIDES', {})

            for data in [d for d in certs.values() if d.get('type') == 'ca']:
                config['OVERRIDES'][data['serial']] = {}
                if data.get('password'):
                    config['OVERRIDES'][data['serial']]['password'] = data['password']

        return profiles

    def get_cert_context(self, name):
        # Get a dictionary suitable for testing output based on the dictionary in basic.certs
        ctx = {}
        for key, value in certs[name].items():
            if key == 'precert_poison':
                ctx['precert_poison'] = 'PrecertPoison (critical): Yes'
            elif key == 'precertificate_signed_certificate_timestamps_serialized':
                ctx['sct_critical'] = ' (critical)' if value['critical'] else ''
                ctx['sct_values'] = []
                for value in value['value']:
                    ctx['sct_values'].append(value)
            elif key == 'precertificate_signed_certificate_timestamps':
                continue  # special extension b/c it cannot be created
            elif key == 'pathlen':
                ctx[key] = value
                ctx['%s_text' % key] = 'unlimited' if value is None else value
            elif isinstance(value, Extension):
                ctx[key] = value

                if isinstance(value, ListExtension):
                    for i, val in enumerate(value):
                        ctx['%s_%s' % (key, i)] = val

                else:
                    ctx['%s_text' % key] = value.as_text()

                if value.critical:
                    ctx['%s_critical' % key] = ' (critical)'
                else:
                    ctx['%s_critical' % key] = ''
            else:
                ctx[key] = value

            if isinstance(value, IterableExtension):
                for i, ext_value in enumerate(value.serialize_iterable()):
                    ctx['%s_%s' % (key, i)] = ext_value

        if certs[name].get('parent'):
            parent = certs[certs[name]['parent']]
            ctx['parent_name'] = parent['name']
            ctx['parent_serial'] = parent['serial']

        if certs[name]['key_filename'] is not False:
            ctx['key_path'] = ca_storage.path(certs[name]['key_filename'])
        return ctx

    def get_idp_full_name(self, ca):
        crl_url = [url.strip() for url in ca.crl_url.split()]
        return [x509.UniformResourceIdentifier(c) for c in crl_url] or None

    def get_idp(self, full_name=None, indirect_crl=False, only_contains_attribute_certs=False,
                only_contains_ca_certs=False, only_contains_user_certs=False, only_some_reasons=None,
                relative_name=None):
        return x509.Extension(
            oid=ExtensionOID.ISSUING_DISTRIBUTION_POINT,
            value=x509.IssuingDistributionPoint(
                full_name=full_name,
                indirect_crl=indirect_crl,
                only_contains_attribute_certs=only_contains_attribute_certs,
                only_contains_ca_certs=only_contains_ca_certs,
                only_contains_user_certs=only_contains_user_certs,
                only_some_reasons=only_some_reasons,
                relative_name=relative_name
            ), critical=True)

    @classmethod
    def expires(cls, days):
        now = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        return now + timedelta(days + 1)

    @classmethod
    def load_ca(cls, name, x509, enabled=True, parent=None, **kwargs):
        """Load a CA from one of the preloaded files."""
        path = '%s.key' % name

        # set some default values
        kwargs.setdefault('issuer_alt_name', certs[name].get('issuer_alternative_name', ''))
        kwargs.setdefault('crl_url', certs[name].get('crl_url', ''))
        kwargs.setdefault('ocsp_url', certs[name].get('ocsp_url', ''))
        kwargs.setdefault('issuer_url', certs[name].get('issuer_url', ''))

        ca = CertificateAuthority(name=name, private_key_path=path, enabled=enabled, parent=parent, **kwargs)
        ca.x509 = x509  # calculates serial etc
        ca.save()
        return ca

    @classmethod
    def create_csr(cls, subject):
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024, backend=default_backend())
        builder = x509.CertificateSigningRequestBuilder()

        builder = builder.subject_name(x509_name(subject))
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        request = builder.sign(private_key, hashes.SHA256(), default_backend())

        return private_key, request

    @classmethod
    def create_cert(cls, ca, csr, subject, **kwargs):
        cert = Certificate.objects.create_cert(ca, csr, subject=subject, **kwargs)
        cert.full_clean()
        return cert

    @classmethod
    def load_cert(cls, ca, x509, csr=''):
        cert = Certificate(ca=ca, csr=csr)
        cert.x509 = x509
        cert.save()
        return cert

    def create_superuser(self, username='admin', password='admin',
                         email='user@example.com'):  # pragma: no cover
        return User.objects.create_superuser(username=username, password=password, email=email)

    def load_usable_cas(self):
        self.cas.update({k: self.load_ca(name=v['name'], x509=v['pub']['parsed']) for k, v in certs.items()
                        if v.get('type') == 'ca' and k not in self.cas and v['key_filename'] is not False})
        self.cas['child'].parent = self.cas['root']
        self.cas['child'].save()
        self.usable_cas = self.cas

    def load_all_cas(self):
        self.cas.update({k: self.load_ca(name=v['name'], x509=v['pub']['parsed']) for k, v in certs.items()
                        if v.get('type') == 'ca' and k not in self.cas})
        self.cas['child'].parent = self.cas['root']
        self.cas['child'].save()
        self.usable_cas = {name: ca for name, ca in self.cas.items()
                           if certs[name]['key_filename'] is not False}

    def load_generated_certs(self):
        for name, data in [(k, v) for k, v in certs.items()
                           if v['type'] == 'cert' and v['cat'] == 'generated' and k not in self.certs]:
            ca = self.cas[data['ca']]
            csr = data.get('csr', {}).get('pem', '')
            self.certs[name] = self.load_cert(ca, x509=data['pub']['parsed'], csr=csr)

        self.generated_certs = self.certs
        self.ca_certs = {k: v for k, v in self.certs.items()
                         if k in ['root-cert', 'child-cert', 'ecc-cert', 'dsa-cert', 'pwd-cert']}

    def load_all_certs(self):
        for name, data in [(k, v) for k, v in certs.items() if v['type'] == 'cert' and k not in self.certs]:
            ca = self.cas[data['ca']]
            csr = data.get('csr', {}).get('pem', '')
            self.certs[name] = self.load_cert(ca, x509=data['pub']['parsed'], csr=csr)

        self.generated_certs = {k: v for k, v in self.certs.items() if certs[k]['cat'] == 'generated'}
        self.ca_certs = {k: v for k, v in self.certs.items()
                         if k in ['root-cert', 'child-cert', 'ecc-cert', 'dsa-cert', 'pwd-cert']}

    @contextmanager
    def patch(self, *args, **kwargs):
        with patch(*args, **kwargs) as mock:
            yield mock

    @contextmanager
    def patch_object(self, *args, **kwargs):  # pragma: only SCT
        with patch.object(*args, **kwargs) as mock:
            yield mock

    @contextmanager
    def mute_celery(self):
        with patch('celery.app.task.Task.apply_async') as mock:
            yield mock


class DjangoCATestCase(DjangoCATestCaseMixin, TestCase):
    pass


@override_settings(CA_MIN_KEY_SIZE=512)
class DjangoCAWithCATestCase(DjangoCATestCase):
    """A test class that already has a CA predefined."""

    def setUp(self):
        super(DjangoCAWithCATestCase, self).setUp()
        self.load_all_cas()


class DjangoCAWithGeneratedCAsTestCase(DjangoCATestCase):
    def setUp(self):
        super(DjangoCAWithGeneratedCAsTestCase, self).setUp()
        self.load_usable_cas()


class DjangoCAWithGeneratedCertsTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(DjangoCAWithGeneratedCertsTestCase, self).setUp()
        self.load_generated_certs()


class DjangoCAWithCertTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(DjangoCAWithCertTestCase, self).setUp()
        self.load_all_certs()


class SeleniumTestCase(DjangoCATestCaseMixin, StaticLiveServerTestCase):  # pragma: no cover
    # NOTE: coverage has weird issues all over this class

    @classmethod
    def setUpClass(cls):
        super(SeleniumTestCase, cls).setUpClass()
        if settings.SKIP_SELENIUM_TESTS:
            return

        if settings.VIRTUAL_DISPLAY:
            cls.vdisplay = Display(visible=0, size=(1024, 768))
            cls.vdisplay.start()

        cls.selenium = WebDriver(
            executable_path=settings.GECKODRIVER_PATH,
            service_log_path=settings.GECKODRIVER_LOG_PATH
        )
        cls.selenium.implicitly_wait(10)

    @classmethod
    def tearDownClass(cls):
        if settings.SKIP_SELENIUM_TESTS:
            super(SeleniumTestCase, cls).tearDownClass()
            return

        cls.selenium.quit()
        if settings.VIRTUAL_DISPLAY:
            cls.vdisplay.stop()
        super(SeleniumTestCase, cls).tearDownClass()

    def find(self, selector):
        """Find an element by CSS selector."""

        return self.selenium.find_element_by_css_selector(selector)

    def login(self, username='admin', password='admin'):
        self.selenium.get('%s%s' % (self.live_server_url, reverse('admin:login')))
        self.find('#id_username').send_keys(username)
        self.find('#id_password').send_keys(password)
        self.find('input[type="submit"]').click()
        self.wait_for_page_load()

    def wait_for_page_load(self, wait=2):
        WebDriverWait(self.selenium, wait).until(lambda driver: driver.find_element_by_tag_name('body'))
