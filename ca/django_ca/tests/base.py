"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

import inspect
import os
import re
import shutil
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

from django.conf import settings
from django.contrib.messages import get_messages
from django.core.management import ManagementUtility
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.test.utils import override_settings as _override_settings
from django.utils.encoding import force_text
from django.utils.six import StringIO
from django.utils.six.moves import reload_module

from .. import ca_settings
from ..extensions import Extension
from ..models import Certificate
from ..models import CertificateAuthority
from ..signals import post_create_ca
from ..signals import post_issue_cert
from ..signals import post_revoke_cert
from ..subject import Subject
from ..utils import OID_NAME_MAPPINGS
from ..utils import get_cert_profile_kwargs
from ..utils import x509_name

if six.PY2:  # pragma: only py2
    from mock import Mock
    from mock import patch
else:  # pragma: only py3
    from unittest.mock import Mock
    from unittest.mock import patch


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
root_key = _load_key('root.key')
root_pem, root_pubkey = _load_cert('root.pem')
child_key = _load_key('child.key')
child_pem, child_pubkey = _load_cert('child.pem')
pwd_ca_pwd = b'test_password'
pwd_ca_key = _load_key('pwd_ca.key', password=pwd_ca_pwd)
pwd_ca_pem, pwd_ca_pubkey = _load_cert('pwd_ca.pem')
ecc_ca_key = _load_key('ecc_ca.key')
ecc_ca_pem, ecc_ca_pubkey = _load_cert('ecc_ca.pem')

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

certs = {
    'root': {
        'name': 'root',
        'pem': force_text(root_pem),
        'serial': '4E:1E:2A:29:F9:4C:45:CF:12:2F:2B:17:9E:BF:D4:80:29:C6:37:C7',
        'md5': '63:C1:A3:28:B4:01:80:A3:96:22:23:96:57:17:98:7D',
        'sha1': '98:10:30:97:99:DB:85:29:74:E6:D0:5E:EE:C8:C5:B7:06:BA:D1:19',
        'sha256': 'DA:0B:C6:6A:60:79:70:94:E1:D2:BE:68:F4:E8:FD:02:80:2A:A9:DF:85:52:49:5F:99:31:DA:15:D7:BF:BA:2E',  # NOQA
        'sha512': '12:33:63:35:91:95:69:58:B5:D0:44:1F:12:C4:40:FD:08:21:86:53:E5:05:9D:C5:49:EC:59:B5:27:63:21:AE:52:F5:BD:AA:B9:BB:F4:A1:42:BD:71:48:5B:7D:1D:0A:54:BD:2A:1F:C4:70:C5:F7:57:94:19:A8:C6:DB:B3:9D', # NOQA
        'san': None,
        'authKeyIdentifier': 'keyid:79:26:89:D2:5D:D8:E1:2C:31:71:EF:AD:38:B4:B6:29:F1:37:28:47',
        'hpkp': 'MWvvGs9cF37mKmi2iXqBBqpkBT8zaWfT09DRSlpg8tQ=',
        'crl': None,
        'subjectKeyIdentifier': '79:26:89:D2:5D:D8:E1:2C:31:71:EF:AD:38:B4:B6:29:F1:37:28:47',
        'dn': '/C=AT/ST=Vienna/L=Vienna/O=example/OU=example/CN=ca.example.com',
        'key_size': 4096,
        'basicConstraints': (True, 'CA:TRUE, pathlen:1'),
        'keyUsage': (True, ['cRLSign', 'keyCertSign']),
        'expires': datetime(2027, 4, 16, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
    'child': {
        'name': 'child',
        'pem': force_text(child_pem),
        'serial': '32:BE:A9:E8:7E:21:BF:3E:E9:A1:F3:F9:E4:06:14:B4:C4:9D:B2:6C',
        'md5': '63:C1:A3:28:B4:01:80:A3:96:22:23:96:57:17:98:7D',
        'sha1': '98:10:30:97:99:DB:85:29:74:E6:D0:5E:EE:C8:C5:B7:06:BA:D1:19',
        'sha256': 'DA:0B:C6:6A:60:79:70:94:E1:D2:BE:68:F4:E8:FD:02:80:2A:A9:DF:85:52:49:5F:99:31:DA:15:D7:BF:BA:2E',  # NOQA
        'sha512': '12:33:63:35:91:95:69:58:B5:D0:44:1F:12:C4:40:FD:08:21:86:53:E5:05:9D:C5:49:EC:59:B5:27:63:21:AE:52:F5:BD:AA:B9:BB:F4:A1:42:BD:71:48:5B:7D:1D:0A:54:BD:2A:1F:C4:70:C5:F7:57:94:19:A8:C6:DB:B3:9D', # NOQA
        'san': None,
        'authKeyIdentifier': 'keyid:79:26:89:D2:5D:D8:E1:2C:31:71:EF:AD:38:B4:B6:29:F1:37:28:47',
        'hpkp': '5Wpp4svwRWrKl3WeBIExoOl3a6/QK3WZAaIPRpgVrBA=',
        'crl': None,  # TODO: add a CRL
        'dn': '/C=AT/ST=Vienna/L=Vienna/O=example/OU=example/CN=sub.ca.example.com',
        'subjectKeyIdentifier': '4A:D5:57:27:D8:CC:01:B7:EF:AE:C1:FE:9A:9F:56:73:36:C3:0B:74',
        'keyUsage': (True, ['cRLSign', 'keyCertSign']),
        'basicConstraints': (True, 'CA:TRUE, pathlen:0'),
        'expires': datetime(2027, 4, 16, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
    'ecc_ca': {
        'name': 'ecc_ca',
        'serial': '52:F4:84:51:D7:38:D9:E6:83:43:7A:4A:1D:EB:ED:A0:7D:6A:7F:D9',
    },
    'pwd_ca': {
        'name': 'pwd_ca',
        'serial': '61:0A:D4:09:CE:18:6A:12:D6:69:F2:68:7D:4D:1A:7C:E9:89:02:62',
    },
    'cert1': {
        'pem': force_text(cert1_pem),
        'hpkp': 'ZHsPuAAhLPHXbSjBW8/2/CylrtpcPlNUcLDMmuMtiWY=',
        'md5': '7B:42:32:BB:7F:C1:E5:CE:3C:ED:1B:74:2F:36:4B:44',
        'sha1': '69:CA:37:7F:82:E5:6E:D9:7B:5A:72:60:F8:94:C6:2B:99:C1:2D:EA',
        'sha256': '88:99:CB:BE:D8:31:9F:76:08:4F:13:03:98:96:81:8D:35:92:E4:11:0D:72:62:F6:00:B9:1A:0F:CB:8B:60:1B',  # NOQA
        'sha512': '51:9E:A7:43:8D:9A:E4:E0:AA:94:C0:4E:60:7F:5E:42:CD:03:E1:E9:D3:93:CB:A6:70:C1:D8:F2:D4:31:F3:A2:F3:17:D6:73:90:DC:66:F3:0F:65:FD:46:BB:BB:FA:1E:AC:D9:FC:D4:80:9F:38:A3:47:71:28:CD:DD:C2:32:F1', # NOQA
        'san': (False, ['DNS:host1.example.com']),
        'cn': 'host1.example.com',
        'keyUsage': (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']),
        'from': '2017-04-17 11:47',
        'until': '2019-04-18 00:00',
        'status': 'Valid',
        'subjectKeyIdentifier': 'D2:1B:D1:90:35:0E:44:58:F7:0A:21:BB:DC:BE:3D:7F:ED:83:E4:FA',
        'authKeyIdentifier': 'keyid:79:26:89:D2:5D:D8:E1:2C:31:71:EF:AD:38:B4:B6:29:F1:37:28:47',
        'issuerAltName': (False, 'URI:https://ca.example.com'),
        'authInfoAccess': (False, ['OCSP - URI:http://ocsp.ca.example.com',
                                   'CA Issuers - URI:http://ca.example.com/ca.crt']),
        'crl': (False, ['Full Name: URI:http://ca.example.com/crl']),
        'der': cert1_pubkey.public_bytes(encoding=Encoding.DER),
        'serial': '5A:1B:A2:63:A1:E4:D8:D1:4D:82:60:46:D3:8F:E0:C3:A5:B3:E4:89',
        'expires': datetime(2019, 4, 18, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
    'cert2': {
        'issuerAltName': (False, 'URI:https://ca.example.com'),
        'md5': '4B:1C:B9:1E:34:B3:E0:7A:F9:95:E4:92:94:54:19:6B',
        'sha1': '3B:EB:92:1C:99:0D:E9:C6:57:2E:ED:A0:25:00:84:21:9E:37:25:87',
        'sha256': 'A2:18:2B:7E:5D:A3:A8:64:B4:9B:74:D5:4A:FB:46:60:DC:B7:A5:20:ED:0E:0E:EC:7A:2E:20:01:20:E9:3F:4C',  # NOQA
        'sha512': '63:86:08:13:70:6E:A2:C3:95:2B:E6:33:16:D8:1C:6E:48:FA:7B:73:6D:51:D0:98:AD:7D:F3:9F:79:5C:03:A0:21:23:DA:88:5C:DD:BB:03:86:E0:A8:77:C3:36:46:06:E9:AA:0C:02:A5:56:81:2B:04:1A:37:11:2A:DE:A2:A5', # NOQA
        'san': (False, ['DNS:host2.example.com']),
        'authKeyIdentifier': 'keyid:79:26:89:D2:5D:D8:E1:2C:31:71:EF:AD:38:B4:B6:29:F1:37:28:47',
        'hpkp': 'i+ccTaizbK5r9luNHFW358cxzaORJ4rS3WYHlEnaQoI=',
        'crl': (False, ['Full Name: URI:http://ca.example.com/crl']),
        'serial': '4E:2B:01:C4:8B:CC:1F:71:94:12:88:64:68:0C:AA:04:D3:F8:BB:45',
        'expires': datetime(2019, 4, 18, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
    'cert3': {
        'issuerAltName': (False, 'URI:https://ca.example.com'),
        'md5': '43:47:4B:6D:7C:7E:3A:BB:85:AF:0F:2E:70:2B:12:07',
        'sha1': '28:65:FB:33:4E:60:DD:44:22:5D:5F:61:FF:C0:6C:FB:3F:23:55:87',
        'sha256': '2A:18:6B:D9:B4:A9:B7:12:17:41:20:A6:6C:D4:AA:0D:D7:98:A0:5F:53:26:C7:47:AA:00:A4:2C:DF:7A:07:96',  # NOQA
        'sha512': 'B2:E8:35:D7:56:37:DA:76:B7:F7:94:5C:A5:66:A7:6E:CC:A7:18:26:35:DC:1C:AD:AC:27:56:83:CA:4E:FD:66:4B:E9:89:6E:D5:A1:7D:94:94:0B:9B:35:E3:45:B5:78:AD:50:8F:CF:5C:9B:1E:16:70:54:B7:76:C4:86:30:66', # NOQA
        'san': (False, ['DNS:host3.example.com']),
        'authKeyIdentifier': 'keyid:79:26:89:D2:5D:D8:E1:2C:31:71:EF:AD:38:B4:B6:29:F1:37:28:47',
        'hpkp': 'ZuJoB0pw8rd2os1WFVe5f8Vky6eg3vHxCrnaZxupFQo=',
        'crl': (False, ['Full Name: URI:http://ca.example.com/crl']),
        'serial': '32:A7:B0:8E:88:A2:1A:EC:05:C8:BA:18:D7:8B:D9:35:45:9D:82:FA',
        'expires': datetime(2019, 4, 18, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
    'ocsp': {
        'crl': (False, ['Full Name: URI:http://ca.example.com/crl']),
        'serial': '49:BC:F2:FE:FA:31:03:B6:E0:CC:3D:16:93:4E:2D:B0:8A:D2:C5:87',
        'expires': datetime(2019, 4, 18, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
}


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
        super(override_tmpcadir, self).enable()

    def disable(self):
        super(override_tmpcadir, self).disable()
        shutil.rmtree(self.options['CA_DIR'])


class DjangoCATestCase(TestCase):
    """Base class for all testcases with some enhancements."""

    re_false_password = r'^(Bad decrypt\. Incorrect password\?|Could not deserialize key data\.)$'

    if six.PY2:  # pragma: only py2
        assertRaisesRegex = TestCase.assertRaisesRegexp

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
        return override_settings(**kwargs)

    def tmpcadir(self, **kwargs):
        return override_tmpcadir(**kwargs)

    def assertBasic(self, cert, algo='SHA256'):
        """Assert some basic key properties."""
        self.assertEqual(cert.version, x509.Version.v3)
        self.assertIsInstance(cert.public_key(), rsa.RSAPublicKey)
        self.assertIsInstance(cert.signature_hash_algorithm, getattr(hashes, algo.upper()))

    def assertSerial(self, serial):
        self.assertIsNotNone(re.match('^[0-9A-F:]*$', serial), serial)

    @contextmanager
    def assertSignal(self, signal):
        handler = Mock()
        signal.connect(handler)
        yield handler
        signal.disconnect(handler)

    def assertMessages(self, response, expected):
        messages = [str(m) for m in list(get_messages(response.wsgi_request))]
        self.assertEqual(messages, expected)

    def assertPostCreateCa(self, post, ca):
        post.assert_called_once_with(ca=ca, signal=post_create_ca, sender=CertificateAuthority)

    def assertPostIssueCert(self, post, cert):
        post.assert_called_once_with(cert=cert, signal=post_issue_cert, sender=Certificate)

    def assertPostRevoke(self, post, cert):
        post.assert_called_once_with(cert=cert, signal=post_revoke_cert, sender=Certificate)

    def assertSubject(self, cert, expected):
        if not isinstance(expected, Subject):
            expected = Subject(expected)
        self.assertEqual(Subject([(s.oid, s.value) for s in cert.subject]), expected)

    def assertIssuer(self, issuer, cert):
        self.assertEqual(cert.issuer, issuer.subject)

    def assertAuthorityKeyIdentifier(self, issuer, cert, critical=False):
        self.assertEqual(cert.authority_key_identifier.value, issuer.subject_key_identifier.value)

    def assertSignature(self, chain, cert):
        # see: http://stackoverflow.com/questions/30700348
        store = X509Store()
        for elem in chain:
            store.add_cert(load_certificate(FILETYPE_PEM, elem.dump_certificate()))

        cert = load_certificate(FILETYPE_PEM, cert.dump_certificate())
        store_ctx = X509StoreContext(store, cert)
        self.assertIsNone(store_ctx.verify_certificate())

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

    def assertNotRevoked(self, cert):
        if isinstance(cert, CertificateAuthority):
            cert = CertificateAuthority.objects.get(serial=cert.serial)
        else:
            cert = Certificate.objects.get(serial=cert.serial)

        self.assertFalse(cert.revoked)
        self.assertIsNone(cert.revoked_reason)

    def assertPrivateKey(self, ca, password=None):
        with open(ca.private_key_path, 'rb') as f:
            key_data = f.read()

        key = serialization.load_pem_private_key(key_data, password, default_backend())
        self.assertIsNotNone(key)
        self.assertTrue(key.key_size > 0)

    @contextmanager
    def assertCommandError(self, msg):
        with self.assertRaisesRegex(CommandError, msg):
            yield

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
            else:
                ctx[key] = value

        return ctx

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
        path = os.path.join(settings.FIXTURES_DIR, '%s.key' % name)
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
            ca=ca, csr=csr, algorithm=hashes.SHA256(), expires=cls.expires(720), subjectAltName=san,
            **cert_kwargs)
        cert.full_clean()
        return cert

    @classmethod
    def load_cert(cls, ca, x509, csr=''):
        cert = Certificate(ca=ca, csr=csr)
        cert.x509 = x509
        cert.save()
        return cert

    def get_cert(self, path):
        return _load_cert(path)

    @classmethod
    def get_subject(cls, cert):
        return {OID_NAME_MAPPINGS[s.oid]: s.value for s in cert.subject}

    @classmethod
    def get_extensions(cls, cert):
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

    @classmethod
    def get_alt_names(cls, x509):
        return cls.get_extensions(x509)['subjectAltName'][1]

    def assertParserError(self, args, expected):
        """Assert that given args throw a parser error."""

        buf = StringIO()
        with self.assertRaises(SystemExit), patch('sys.stderr', buf):
            self.parser.parse_args(args)

        output = buf.getvalue()
        self.assertEqual(output, expected)
        return output

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

    def cmd(self, *args, **kwargs):
        kwargs.setdefault('stdout', StringIO())
        kwargs.setdefault('stderr', StringIO())
        stdin = kwargs.pop('stdin', StringIO())

        with patch('sys.stdin', stdin):
            call_command(*args, **kwargs)
        return kwargs['stdout'].getvalue(), kwargs['stderr'].getvalue()


@override_settings(CA_MIN_KEY_SIZE=512)
class DjangoCAWithCATestCase(DjangoCATestCase):
    """A test class that already has a CA predefined."""

    def setUp(self):
        super(DjangoCAWithCATestCase, self).setUp()
        self.ca = self.load_ca(name='root', x509=root_pubkey)
        self.pwd_ca = self.load_ca(name='pwd_ca', x509=pwd_ca_pubkey)
        self.ecc_ca = self.load_ca(name='ecc_ca', x509=ecc_ca_pubkey)


class DjangoCAWithCSRTestCase(DjangoCAWithCATestCase):
    def setUp(self):
        super(DjangoCAWithCSRTestCase, self).setUp()

        self.key = cert1_key
        self.csr_pem = cert1_csr
        self.csr_der = cert1_csr_der


class DjangoCAWithCertTestCase(DjangoCAWithCSRTestCase):
    def setUp(self):
        super(DjangoCAWithCertTestCase, self).setUp()
        self.cert = self.load_cert(self.ca, x509=cert1_pubkey, csr=cert1_csr)
        self.cert_all = self.load_cert(self.ca, x509=all_pubkey, csr=all_csr)
        self.cert_no_ext = self.load_cert(self.ca, x509=no_ext_pubkey, csr=no_ext_csr)


class DjangoCAWithChildCATestCase(DjangoCAWithCertTestCase):
    def setUp(self):
        super(DjangoCAWithChildCATestCase, self).setUp()
        self.child_ca = self.load_ca(name='child', x509=child_pubkey, parent=self.ca)
