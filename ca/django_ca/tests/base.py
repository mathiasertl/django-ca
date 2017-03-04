"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

import os
import shutil
import tempfile
from datetime import datetime
from datetime import timedelta

from mock import patch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from django.conf import settings
from django.core.management import call_command
from django.test import TestCase
from django.test.utils import override_settings as _override_settings
from django.utils.six import StringIO
from django.utils.six.moves import reload_module

from .. import ca_settings
from ..models import Certificate
from ..models import CertificateAuthority
from ..utils import OID_NAME_MAPPINGS
from ..utils import get_cert_profile_kwargs
from ..utils import sort_subject_dict
from ..utils import x509_name


def _load_key(path):
    path = os.path.join(settings.FIXTURES_DIR, path)
    with open(path, 'rb') as stream:
        return serialization.load_pem_private_key(stream.read(), password=None, backend=default_backend())


def _load_csr(path):
    path = os.path.join(settings.FIXTURES_DIR, path)
    with open(path, 'r') as stream:
        return stream.read().strip()


def _load_cert(path):
    path = os.path.join(settings.FIXTURES_DIR, path)
    with open(path, 'rb') as stream:
        pem = stream.read()
        return pem, x509.load_pem_x509_certificate(pem, default_backend())


root_key = _load_key('root.key')
root_pem, root_pubkey = _load_cert('root.pem')
child_key = _load_key('child.key')
child_pem, child_pubkey = _load_cert('child.pem')
child_serial = '6A:A2:3D:F9:5A:4A:44:8A:9F:91:64:54:A2:0D:04:29'
ocsp_key = _load_key('ocsp.key')
ocsp_csr = _load_csr('ocsp.csr')
ocsp_pem, ocsp_pubkey = _load_cert('ocsp.pem')
cert1_key = _load_key('cert1.key')
cert1_csr = _load_csr('cert1.csr')
cert1_pem, cert1_pubkey = _load_cert('cert1.pem')
cert1_serial = '23:14:E2:ED:5F:5B:49:0F:BB:DA:14:00:4A:C8:A1:1B'
cert2_key = _load_key('cert2.key')
cert2_csr = _load_csr('cert2.csr')
cert2_pem, cert2_pubkey = _load_cert('cert2.pem')
cert2_serial = '26:F2:78:85:6B:46:46:67:B0:12:1C:0B:CB:0F:85:43'
cert3_key = _load_key('cert3.key')
cert3_csr = _load_csr('cert3.csr')
cert3_pem, cert3_pubkey = _load_cert('cert3.pem')
cert3_serial = 'A0:36:C7:6B:91:36:44:4C:85:0F:34:E7:F6:D0:42:5E'


class override_settings(_override_settings):
    """Enhance override_settings to also reload django_ca.ca_settings.

    .. WARNING:: When using this class as a class decorator, the decorated class must inherit from
       :py:class:`~django_ca.tests.base.DjangoCATestCase`.
    """

    def __call__(self, test_func):
        if isinstance(test_func, type) and not issubclass(test_func, DjangoCATestCase):
            raise Exception("Only subclasses of DjangoCATestCase can use override_settings.")
        inner = super(override_settings, self).__call__(test_func)
        return inner

    def save_options(self, test_func):
        super(override_settings, self).save_options(test_func)
        reload_module(ca_settings)

    def enable(self):
        super(override_settings, self).enable()
        reload_module(ca_settings)

    def disable(self):
        super(override_settings, self).disable()
        reload_module(ca_settings)


class override_tmpcadir(override_settings):
    """Sets the CA_DIR directory to a temporary directory.

    .. NOTE: This also takes any additional settings.
    """

    def __init__(self, **kwargs):
        super(override_tmpcadir, self).__init__(**kwargs)
        self.options['CA_DIR'] = tempfile.mkdtemp()

    def disable(self):
        super(override_tmpcadir, self).disable()
        shutil.rmtree(self.options['CA_DIR'])


class DjangoCATestCase(TestCase):
    """Base class for all testcases with some enhancements."""

    @classmethod
    def setUpClass(cls):
        super(DjangoCATestCase, cls).setUpClass()

        if cls._overridden_settings:
            reload_module(ca_settings)

    @classmethod
    def tearDownClass(cls):
        overridden = False
        ca_dir = None
        if hasattr(cls, '_cls_overridden_context'):
            overridden = True
            ca_dir = cls._cls_overridden_context.options.get('CA_DIR')

        super(DjangoCATestCase, cls).tearDownClass()

        if overridden is True:
            reload_module(ca_settings)
            if ca_dir is not None:
                shutil.rmtree(ca_dir)

    def setUp(self):
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

    def assertSubject(self, cert, expected):
        actual = [(OID_NAME_MAPPINGS[s.oid], s.value) for s in cert.subject]
        self.assertEqual(actual, sort_subject_dict(expected))

    def assertIssuer(self, issuer, cert):
        self.assertEqual(cert.issuer, issuer.subject)

    def assertAuthorityKeyIdentifier(self, issuer, cert):
        self.assertEqual(cert.authorityKeyIdentifier().strip(),
                         'keyid:%s' % issuer.subjectKeyIdentifier())

    @classmethod
    def expires(cls, days):
        now = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        return now + timedelta(days + 1)

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
    def create_csr(cls, **subject):
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
        cert_kwargs.setdefault('subject', {})
        cert_kwargs['subject'].update(subject)
        x509 = Certificate.objects.init(
            ca=ca, csr=csr, algorithm=hashes.SHA256(), expires=cls.expires(720), subjectAltName=san,
            **cert_kwargs)

        cert = Certificate(ca=ca, csr=csr)
        cert.x509 = x509
        cert.expires = cert.not_after  # this comes from the cert
        cert.save()
        return cert

    @classmethod
    def load_cert(cls, ca, x509):
        cert = Certificate(ca=ca, csr='none')
        cert.x509 = x509
        cert.save()
        return cert

    @classmethod
    def get_subject(cls, cert):
        value = {OID_NAME_MAPPINGS[s.oid]: s.value for s in cert.subject}
        if 'EMAILADDRESS' in value:
            value['emailAddress'] = value.pop('EMAILADDRESS')
        return value

    @classmethod
    def get_extensions(cls, cert):
        c = Certificate()
        c.x509 = cert
        exts = [e.oid._name for e in cert.extensions]
        if 'cRLDistributionPoints' in exts:
            exts.remove('cRLDistributionPoints')
            exts.append('crlDistributionPoints')
        return {name: getattr(c, name)() for name in exts}

    @classmethod
    def get_alt_names(cls, x509):
        return [n.strip() for n in cls.get_extensions(x509)['subjectAltName'].split(',')]

    def assertParserError(self, args, expected):
        """Assert that given args throw a parser error."""

        buf = StringIO()
        with self.assertRaises(SystemExit), patch('sys.stderr', buf):
            self.parser.parse_args(args)

        output = buf.getvalue()
        self.assertEqual(output, expected)
        return output

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

    @classmethod
    def setUpClass(cls):
        super(DjangoCAWithCATestCase, cls).setUpClass()
        cls.ca = cls.load_ca(name='root', x509=root_pubkey)


class DjangoCAWithCSRTestCase(DjangoCAWithCATestCase):
    @classmethod
    def setUpClass(cls):
        super(DjangoCAWithCSRTestCase, cls).setUpClass()

        cls.key = cert1_key
        cls.csr_pem = cert1_csr


class DjangoCAWithCertTestCase(DjangoCAWithCSRTestCase):
    @classmethod
    def setUpClass(cls):
        super(DjangoCAWithCertTestCase, cls).setUpClass()
        cls.cert = cls.load_cert(cls.ca, x509=cert1_pubkey)
