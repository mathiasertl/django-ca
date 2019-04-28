"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

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

import six
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
from django.contrib.messages import get_messages
from django.core.exceptions import ValidationError
from django.core.management import ManagementUtility
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.test.utils import override_settings as _override_settings
from django.utils.encoding import force_text
from django.utils.six import StringIO
from django.utils.six.moves import reload_module

from .. import ca_settings
from ..extensions import AuthorityInformationAccess
from ..extensions import AuthorityKeyIdentifier
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import Extension
from ..extensions import IssuerAlternativeName
from ..extensions import KeyUsage
from ..extensions import ListExtension
from ..extensions import NameConstraints
from ..extensions import OCSPNoCheck
from ..extensions import SubjectAlternativeName
from ..extensions import SubjectKeyIdentifier
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import CertificateAuthority
from ..profiles import get_cert_profile_kwargs
from ..signals import post_create_ca
from ..signals import post_issue_cert
from ..signals import post_revoke_cert
from ..subject import Subject
from ..utils import OID_NAME_MAPPINGS
from ..utils import ca_storage
from ..utils import x509_name

if six.PY2:  # pragma: only py2
    from mock import Mock
    from mock import patch

    from testfixtures import LogCapture  # for capturing logging
else:  # pragma: only py3
    from unittest.mock import Mock
    from unittest.mock import patch

if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: no branch, pragma: only cryptography>=2.4
    from ..extensions import PrecertPoison


def _load_key(path, password=None):
    path = os.path.join(settings.FIXTURES_DIR, path)
    with open(path, 'rb') as stream:
        return serialization.load_pem_private_key(stream.read(), password=password, backend=default_backend())


def _load_csr(path):
    path = os.path.join(settings.FIXTURES_DIR, path)
    with open(path, 'r') as stream:
        return stream.read().strip()


def _load_cert(path):
    path = os.path.join(settings.FIXTURES_DIR, path)
    with open(path, 'rb') as stream:
        pem = stream.read()
        return pem, x509.load_pem_x509_certificate(pem, default_backend())


cryptography_version = tuple([int(t) for t in cryptography.__version__.split('.')[:2]])

ocsp_key = _load_key('ocsp.key')
ocsp_csr = _load_csr('ocsp.csr')
ocsp_pem, ocsp_pubkey = _load_cert('ocsp.pem')
cert1_key = _load_key('cert1.key')
cert1_csr = _load_csr('cert1.csr')
with open(os.path.join(settings.FIXTURES_DIR, 'cert1-der.csr'), 'rb') as stream:
    cert1_csr_der = stream.read()

cert1_pem, cert1_pubkey = _load_cert('cert1.pem')
cert1_csr = _load_csr('cert1.csr')
cert2_key = _load_key('cert2.key')
cert2_csr = _load_csr('cert2.csr')
cert2_pem, cert2_pubkey = _load_cert('cert2.pem')
cert3_key = _load_key('cert3.key')
cert3_csr = _load_csr('cert3.csr')
cert3_pem, cert3_pubkey = _load_cert('cert3.pem')

# this cert has (most) extensions we currently handle
all_key = _load_key('all.key')
all_csr = _load_csr('all.csr')
all_pem, all_pubkey = _load_cert('all.pem')

# this cert has *no* extensions
no_ext_key = _load_key('cert_no_ext.key')
no_ext_csr = _load_csr('cert_no_ext.csr')
no_ext_pem, no_ext_pubkey = _load_cert('cert_no_ext.pem')

# Various contributed certs
_, multiple_ous_and_no_ext_pubkey = _load_cert(os.path.join('contrib', 'multiple_ous_and_no_ext.pem'))
_, cloudflare_1_pubkey = _load_cert(os.path.join('contrib', 'cloudflare_1.pem'))
_, letsencrypt_jabber_at_pubkey = _load_cert(os.path.join('contrib', 'letsencrypt_jabber_at.pem'))
_, godaddy_derstandardat_pubkey = _load_cert(os.path.join('contrib', 'godaddy_derstandardat.pem'))

# some reused values
root_keyid = '79:26:89:D2:5D:D8:E1:2C:31:71:EF:AD:38:B4:B6:29:F1:37:28:47'
root_crl_url = 'http://ca.example.com/crl'
root_issuer_url = 'http://ca.example.com/ca.crt'
root_issuer_alt = 'http://ca.example.com/'
root_ocsp_url = 'http://ocsp.ca.example.com'
root_ocsp_domain = 'ocsp.ca.example.com'

certs = {
    'cert1': {
        'san': SubjectAlternativeName('DNS:host1.example.com'),
        'cn': 'host1.example.com',
        'keyUsage': (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']),
        'status': 'Valid',
        'issuer_alternative_name': 'URI:https://ca.example.com',
        'der': cert1_pubkey.public_bytes(encoding=Encoding.DER),
    },
    'cert2': {
        'issuer_alternative_name': 'URI:https://ca.example.com',
        'san': SubjectAlternativeName('DNS:host2.example.com'),
    },
    'cert3': {
        'issuer_alternative_name': 'URI:https://ca.example.com',
        'san': SubjectAlternativeName('DNS:host3.example.com'),
    },

    # created using django_ca.tests.tests_managers.GetCertTestCase.test_all_extensions
    'cert_all': {
        'cn': 'all-extensions.example.com',
        'status': 'Valid',
        'authority_information_access': AuthorityInformationAccess({
            'issuers': ['URI:%s' % root_issuer_url],
            'ocsp': ['URI:%s' % root_ocsp_url],
        }),
        'authority_key_identifier': AuthorityKeyIdentifier(root_keyid),
        'basic_constraints': BasicConstraints('critical,CA:FALSE'),
        'extended_key_usage': ExtendedKeyUsage('serverAuth,clientAuth,codeSigning,emailProtection'),
        'issuer_alternative_name': IssuerAlternativeName('URI:%s' % root_issuer_alt),
        'key_usage': KeyUsage('critical,encipherOnly,keyAgreement,nonRepudiation'),
        'name_constraints': NameConstraints([['DNS:.com'], ['DNS:.net']]),
        'ocsp_no_check': OCSPNoCheck({'critical': True}),
        'precert_poison': True,  # only set once we require cryptography>=2.4
        'subject_alternative_name': SubjectAlternativeName('DNS:all-extensions.example.com,DNS:extra.example.com'),  # NOQA
        'tls_feature': TLSFeature('critical,OCSPMustStaple,MultipleCertStatusRequest'),
    },
    'ocsp': {
        'cn': root_ocsp_domain,
        'status': 'Valid',
        'authority_information_access': AuthorityInformationAccess({
            'issuers': ['URI:http://ca.example.com/ca.crt'],
        }),
        'authority_key_identifier': AuthorityKeyIdentifier(root_keyid),
        'basic_constraints': BasicConstraints('critical,CA:FALSE'),
        'extended_key_usage': ExtendedKeyUsage('OCSPSigning'),
        'issuer_alternative_name': IssuerAlternativeName('URI:%s' % root_issuer_alt),
        'key_usage': KeyUsage('critical,digitalSignature,keyEncipherment,nonRepudiation'),
        'ocsp_no_check': OCSPNoCheck(),
        'subject_alternative_name': SubjectAlternativeName('DNS:%s' % root_ocsp_domain),
    },

    # contrib certificates
    'cloudflare_1': {
        'cn': 'sni24142.cloudflaressl.com',
        'precert_poison': True,  # only set once we require cryptography>=2.4
    },
}

with open(os.path.join(settings.FIXTURES_DIR, 'cert-data.json')) as stream:
    _fixture_data = json.load(stream)

timestamps = {
    'base': datetime.strptime(_fixture_data['timestamp'], '%Y-%m-%d %H:%M:%S'),
}
timestamps['before_everything'] = timestamps['base'] - timedelta(days=0)
timestamps['before_child'] = timestamps['base'] - timedelta(days=1)
timestamps['everything_valid'] = timestamps['base'] + timedelta(days=10)
timestamps['everything_expired'] = timestamps['base'] + timedelta(days=365 * 20)
certs = _fixture_data.get('certs')

# Load CA keys
root_key = _load_key(certs['root']['key'])
root_pem, root_pubkey = _load_cert(certs['root']['pub'])
child_key = _load_key(certs['child']['key'])
child_pem, child_pubkey = _load_cert(certs['child']['pub'])
pwd_ca_key = _load_key(certs['pwd']['key'], password=certs['pwd']['password'].encode('utf-8'))
pwd_ca_pem, pwd_ca_pubkey = _load_cert(certs['pwd']['pub'])
ecc_ca_key = _load_key(certs['ecc']['key'])
ecc_ca_pem, ecc_ca_pubkey = _load_cert(certs['ecc']['pub'])
dsa_ca_key = _load_key(certs['dsa']['key'])
dsa_ca_pem, dsa_ca_pubkey = _load_cert(certs['dsa']['pub'])

# Load certificates
root_cert_key = _load_key(certs['root-cert']['key'])
root_cert_csr = _load_csr(certs['root-cert']['csr'])
root_cert_pem, root_cert_pubkey = _load_cert(certs['root-cert']['pub'])
child_cert_key = _load_key(certs['child-cert']['key'])
child_cert_csr = _load_csr(certs['child-cert']['csr'])
child_cert_pem, child_cert_pubkey = _load_cert(certs['child-cert']['pub'])
ecc_cert_key = _load_key(certs['ecc-cert']['key'])
ecc_cert_csr = _load_csr(certs['ecc-cert']['csr'])
ecc_cert_pem, ecc_cert_pubkey = _load_cert(certs['ecc-cert']['pub'])
dsa_cert_key = _load_key(certs['dsa-cert']['key'])
dsa_cert_csr = _load_csr(certs['dsa-cert']['csr'])
dsa_cert_pem, dsa_cert_pubkey = _load_cert(certs['dsa-cert']['pub'])
pwd_cert_key = _load_key(certs['pwd-cert']['key'])
pwd_cert_csr = _load_csr(certs['pwd-cert']['csr'])
pwd_cert_pem, pwd_cert_pubkey = _load_cert(certs['pwd-cert']['pub'])

for cert_name, cert_data in certs.items():
    cert_data['valid_from'] = datetime.strptime(cert_data['valid_from'], '%Y-%m-%d %H:%M:%S')
    cert_data['valid_until'] = datetime.strptime(cert_data['valid_until'], '%Y-%m-%d %H:%M:%S')

    cert_data['valid_from_short'] = cert_data['valid_from'].strftime('%Y-%m-%d %H:%M')
    cert_data['valid_until_short'] = cert_data['valid_until'].strftime('%Y-%m-%d %H:%M')

    if cert_data.get('authority_key_identifier'):
        cert_data['authority_key_identifier'] = AuthorityKeyIdentifier(cert_data['authority_key_identifier'])
    if cert_data.get('subject_key_identifier'):
        cert_data['subject_key_identifier'] = SubjectKeyIdentifier(cert_data['subject_key_identifier'])
    if cert_data.get('basic_constraints'):
        cert_data['basic_constraints'] = BasicConstraints(cert_data['basic_constraints'])
    if cert_data.get('extended_key_usage'):
        cert_data['extended_key_usage'] = ExtendedKeyUsage(cert_data['extended_key_usage'])
    if cert_data.get('key_usage'):
        cert_data['key_usage'] = KeyUsage(cert_data['key_usage'])
    if cert_data.get('authority_information_access'):
        cert_data['authority_information_access'] = AuthorityInformationAccess(
            cert_data['authority_information_access'])
    if cert_data.get('subject_alternative_name'):
        cert_data['subject_alternative_name'] = SubjectAlternativeName(cert_data['subject_alternative_name'])

certs['root']['pem'] = force_text(root_pem)
certs['child']['pem'] = force_text(child_pem)
certs['ecc']['pem'] = force_text(ecc_ca_pem)
certs['pwd']['pem'] = force_text(pwd_ca_pem)
certs['dsa']['pem'] = force_text(dsa_ca_pem)
certs['root-cert']['pem'] = force_text(root_cert_pem)
certs['ecc-cert']['pem'] = force_text(ecc_cert_pem)
certs['dsa-cert']['pem'] = force_text(dsa_cert_pem)
certs['pwd-cert']['pem'] = force_text(pwd_cert_pem)
certs['child-cert']['pem'] = force_text(child_cert_pem)


if certs and ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: no branch, pragma: only cryptography>=2.4
    pass  # not there yet
    #certs['cert_all']['precert_poison'] = PrecertPoison()
    #certs['cloudflare_1']['precert_poison'] = PrecertPoison()


class override_settings(_override_settings):
    """Enhance override_settings to also reload django_ca.ca_settings.

    .. WARNING:: When using this class as a class decorator, the decorated class must inherit from
       :py:class:`~django_ca.tests.base.DjangoCATestCase`.
    """

    def __call__(self, test_func):
        if inspect.isclass(test_func) and not issubclass(test_func, DjangoCATestCase):
            raise ValueError("Only subclasses of DjangoCATestCase can use override_settings")
        inner = super(override_settings, self).__call__(test_func)
        return inner

    def save_options(self, test_func):
        super(override_settings, self).save_options(test_func)
        reload_module(ca_settings)

    def enable(self):
        super(override_settings, self).enable()

        try:
            reload_module(ca_settings)
        except Exception:  # pragma: no cover
            # If an exception is thrown reloading ca_settings, we disable everything again.
            # Otherwise an exception in ca_settings will cause overwritten settings to persist
            # to the next tests.
            super(override_settings, self).disable()
            reload_module(ca_settings)
            raise

    def disable(self):
        super(override_settings, self).disable()
        reload_module(ca_settings)


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
        shutil.copy(os.path.join(settings.FIXTURES_DIR, certs['root']['key']), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, certs['child']['key']), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, certs['pwd']['key']), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, certs['ecc']['key']), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, certs['dsa']['key']), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, certs['dsa']['key']), self.options['CA_DIR'])

        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'ocsp.key'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'ocsp.pem'), self.options['CA_DIR'])

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


class DjangoCATestCase(TestCase):
    """Base class for all testcases with some enhancements."""

    re_false_password = r'^(Bad decrypt\. Incorrect password\?|Could not deserialize key data\.)$'

    if six.PY2:  # pragma: no branch, pragma: only py2
        assertRaisesRegex = TestCase.assertRaisesRegexp

        @contextmanager
        def assertLogs(self, logger=None, level=None):
            """Simulate assertLogs() from Python3 using the textfixtures module.

            Note that this context manager only allows you to compare the ouput
            attribute, not the "records" attribute."""

            class Py2LogCapture(object):
                @property
                def output(self):
                    return ['%s:%s:%s' % (r[1], r[0], r[2]) for r in lc.actual()]

            with LogCapture() as lc:
                yield Py2LogCapture()

    @classmethod
    def setUpClass(cls):
        super(DjangoCATestCase, cls).setUpClass()

        if cls._overridden_settings:
            reload_module(ca_settings)

    @classmethod
    def tearDownClass(cls):
        overridden = False
        if hasattr(cls, '_cls_overridden_context'):
            overridden = True

        super(DjangoCATestCase, cls).tearDownClass()

        if overridden is True:
            reload_module(ca_settings)

    def settings(self, **kwargs):
        """Decorator to temporarily override settings."""
        return override_settings(**kwargs)

    def tmpcadir(self, **kwargs):
        """Context manager to use a temporary CA dir."""
        return override_tmpcadir(**kwargs)

    def mock_cadir(self, path):
        return mock_cadir(path)

    def assertAuthorityKeyIdentifier(self, issuer, cert, critical=False):
        self.assertEqual(cert.authority_key_identifier.value, issuer.subject_key_identifier.value)

    def assertBasic(self, cert, algo='SHA256'):
        """Assert some basic key properties."""
        self.assertEqual(cert.version, x509.Version.v3)
        self.assertIsInstance(cert.public_key(), rsa.RSAPublicKey)
        self.assertIsInstance(cert.signature_hash_algorithm, getattr(hashes, algo.upper()))

    def assertCRL(self, crl, certs=None, signer=None, expires=86400, algorithm=None, encoding=Encoding.PEM,
                  idp=None, extensions=None, crl_number=0):
        certs = certs or []
        signer = signer or self.ca
        algorithm = algorithm or ca_settings.CA_DIGEST_ALGORITHM
        extensions = extensions or []
        expires = datetime.utcnow() + timedelta(seconds=expires)

        if idp is not None:  # pragma: no branch, pragma: only cryptography>=2.5
            extensions.append(idp)
        extensions.append(x509.Extension(
            value=x509.CRLNumber(crl_number=crl_number),
            critical=False, oid=ExtensionOID.CRL_NUMBER
        ))
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

    def assertHasExtension(self, cert, oid):
        """Assert that the given cert has the passed extension."""

        self.assertIn(oid, [e.oid for e in cert.x509.extensions])

    def assertHasNotExtension(self, cert, oid):
        """Assert that the given cert does *not* have the passed extension."""
        self.assertNotIn(oid, [e.oid for e in cert.x509.extensions])

    def assertIssuer(self, issuer, cert):
        self.assertEqual(cert.issuer, issuer.subject)

    def assertMessages(self, response, expected):
        messages = [str(m) for m in list(get_messages(response.wsgi_request))]
        self.assertEqual(messages, expected)

    def assertNotRevoked(self, cert):
        if isinstance(cert, CertificateAuthority):
            cert = CertificateAuthority.objects.get(serial=cert.serial)
        else:
            cert = Certificate.objects.get(serial=cert.serial)

        self.assertFalse(cert.revoked)
        self.assertIsNone(cert.revoked_reason)

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
            self.assertIsNone(cert.revoked_reason)
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

    def get_cert_context(self, name):
        # Get a dictionary suitable for testing output based on the dictionary in basic.certs
        ctx = {}
        for key, value in certs[name].items():
            if isinstance(value, tuple):
                crit, val = value
                ctx['%s_critical' % key] = crit

                if isinstance(val, list):
                    for i, val_i in enumerate(val):
                        ctx['%s_%s' % (key, i)] = val_i
                else:
                    ctx[key] = val
            elif key == 'precert_poison':
                # NOTE: We use two keys here because if we don't have PrecertPoison, the name of the
                #       extension is "Unknown OID", so the order is different.
                if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: only cryptography>=2.4
                    ctx['precert_poison'] = '\nPrecertPoison (critical): Yes'
                    ctx['precert_poison_unknown'] = ''
                else:  # pragma: no cover
                    ctx['precert_poison'] = ''
                    oid = '<ObjectIdentifier(oid=1.3.6.1.4.1.11129.2.4.3, name=Unknown OID)>'
                    ctx['precert_poison_unknown'] = '\nUnknownOID (critical):\n    %s' % oid
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

        if certs[name].get('parent'):
            parent = certs[certs[name]['parent']]
            ctx['parent_name'] = parent['name']
            ctx['parent_serial'] = parent['serial']

        ctx['key_path'] = ca_storage.path(certs[name]['key'])
        return ctx

    def get_idp(self, full_name=None, indirect_crl=False, only_contains_attribute_certs=False,
                only_contains_ca_certs=False, only_contains_user_certs=False, only_some_reasons=None,
                relative_name=None):
        if not ca_settings.CRYPTOGRAPHY_HAS_IDP:  # pragma: only cryptography<2.5
            return
        else:  # pragma: only cryptography>=2.5
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
    def create_ca(cls, name, **kwargs):
        """Create a new CA.

        Sets sane defaults for all required kwargs, so you only have to pass the name.
        """

        kwargs.setdefault('key_size', settings.CA_MIN_KEY_SIZE)
        kwargs.setdefault('key_type', 'RSA')
        kwargs.setdefault('algorithm', hashes.SHA256())
        kwargs.setdefault('expires', datetime.now() + timedelta(days=3560))
        kwargs.setdefault('parent', None)
        kwargs.setdefault('subject', Subject('/CN=generated.example.com'))

        ca = CertificateAuthority.objects.init(name=name, **kwargs)
        return ca

    @classmethod
    def load_ca(cls, name, x509, enabled=True, parent=None, **kwargs):
        """Load a CA from one of the preloaded files."""
        path = '%s.key' % name
        ca = CertificateAuthority(name=name, private_key_path=path, enabled=enabled, parent=parent,
                                  **kwargs)
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
    def create_cert(cls, ca, csr, subject, san=None, **kwargs):
        cert_kwargs = get_cert_profile_kwargs()
        cert_kwargs.update(kwargs)
        cert_kwargs['subject'] = Subject(subject)
        cert = Certificate.objects.init(
            ca=ca, csr=csr, algorithm=hashes.SHA256(), expires=cls.expires(720),
            subject_alternative_name=san, **cert_kwargs)
        cert.full_clean()
        return cert

    @classmethod
    def load_cert(cls, ca, x509, csr=''):
        cert = Certificate(ca=ca, csr=csr)
        cert.x509 = x509
        cert.save()
        return cert

    @classmethod
    def get_subject(cls, cert):
        return {OID_NAME_MAPPINGS[s.oid]: s.value for s in cert.subject}

    @classmethod
    def get_extensions(cls, cert):
        # TODO: use cert.get_extensions() as soon as everything is moved to the new framework
        c = Certificate()
        c.x509 = cert
        exts = [e.oid._name for e in cert.extensions]
        if 'cRLDistributionPoints' in exts:
            exts.remove('cRLDistributionPoints')
            exts.append('crlDistributionPoints')

        exts = {}
        for ext in c.get_extensions():
            if isinstance(ext, Extension):
                exts[ext.__class__.__name__] = ext

            # old extension framework
            else:
                name, value = ext
                exts[name] = value

        return exts


@override_settings(CA_MIN_KEY_SIZE=512)
class DjangoCAWithCATestCase(DjangoCATestCase):
    """A test class that already has a CA predefined."""

    def setUp(self):
        super(DjangoCAWithCATestCase, self).setUp()
        self.ca = self.load_ca(name=certs['root']['name'], x509=root_pubkey)
        self.child_ca = self.load_ca(name=certs['child']['name'], x509=child_pubkey, parent=self.ca)
        self.pwd_ca = self.load_ca(name=certs['pwd']['name'], x509=pwd_ca_pubkey)
        self.ecc_ca = self.load_ca(name=certs['ecc']['name'], x509=ecc_ca_pubkey)
        self.dsa_ca = self.load_ca(name=certs['dsa']['name'], x509=dsa_ca_pubkey)
        self.cas = [self.ca, self.pwd_ca, self.ecc_ca, self.child_ca, self.dsa_ca]


class DjangoCAWithCSRTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(DjangoCAWithCSRTestCase, self).setUp()

        self.key = cert1_key
        self.csr_pem = cert1_csr
        self.csr_der = cert1_csr_der


class DjangoCAWithCertTestCase(DjangoCAWithCSRTestCase):
    def setUp(self):
        super(DjangoCAWithCertTestCase, self).setUp()
        self.root_cert = self.load_cert(self.ca, x509=root_cert_pubkey, csr=root_cert_csr)
        self.child_cert = self.load_cert(self.child_ca, x509=child_cert_pubkey, csr=child_cert_csr)
        self.pwd_cert = self.load_cert(self.pwd_ca, x509=pwd_cert_pubkey, csr=pwd_cert_csr)
        self.ecc_cert = self.load_cert(self.ecc_ca, x509=ecc_cert_pubkey, csr=ecc_cert_csr)
        self.dsa_cert = self.load_cert(self.dsa_ca, x509=dsa_cert_pubkey, csr=dsa_cert_csr)

        # These are the basic certificates loaded in a loop
        self.basic_certs = {
            'root-cert': self.root_cert,
            'child-cert': self.child_cert,
            'pwd-cert': self.pwd_cert,
            'ecc-cert': self.ecc_cert,
            'dsa-cert': self.dsa_cert,
        }

        self.ocsp = self.load_cert(self.ca, ocsp_pubkey)
        self.cert_all = self.load_cert(self.ca, x509=all_pubkey, csr=all_csr)
        self.cert_no_ext = self.load_cert(self.ca, x509=no_ext_pubkey, csr=no_ext_csr)

        # the one with no hostname:
        self.cert_multiple_ous_and_no_ext = self.load_cert(self.ca, multiple_ous_and_no_ext_pubkey)

        self.cert_cloudflare_1 = self.load_cert(self.ca, cloudflare_1_pubkey)
        self.cert_letsencrypt_jabber_at = self.load_cert(self.ca, letsencrypt_jabber_at_pubkey)
        self.cert_godaddy_derstandardat = self.load_cert(self.ca, godaddy_derstandardat_pubkey)

        self.certs = [
            self.ocsp, self.cert_all, self.cert_no_ext,
            self.cert_multiple_ous_and_no_ext, self.cert_cloudflare_1, self.cert_letsencrypt_jabber_at,
            self.cert_godaddy_derstandardat,
        ]


class DjangoCAWithChildCATestCase(DjangoCAWithCertTestCase):
    pass  # TODO: remove
