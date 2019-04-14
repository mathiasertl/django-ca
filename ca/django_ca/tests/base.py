"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

import inspect
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
    'root': {
        'name': 'root',
        'pem': force_text(root_pem),
        'serial': '4E:1E:2A:29:F9:4C:45:CF:12:2F:2B:17:9E:BF:D4:80:29:C6:37:C7',
        'md5': '63:C1:A3:28:B4:01:80:A3:96:22:23:96:57:17:98:7D',
        'sha1': '98:10:30:97:99:DB:85:29:74:E6:D0:5E:EE:C8:C5:B7:06:BA:D1:19',
        'sha256': 'DA:0B:C6:6A:60:79:70:94:E1:D2:BE:68:F4:E8:FD:02:80:2A:A9:DF:85:52:49:5F:99:31:DA:15:D7:BF:BA:2E',  # NOQA
        'sha512': '12:33:63:35:91:95:69:58:B5:D0:44:1F:12:C4:40:FD:08:21:86:53:E5:05:9D:C5:49:EC:59:B5:27:63:21:AE:52:F5:BD:AA:B9:BB:F4:A1:42:BD:71:48:5B:7D:1D:0A:54:BD:2A:1F:C4:70:C5:F7:57:94:19:A8:C6:DB:B3:9D', # NOQA
        'san': None,
        'authKeyIdentifier': 'keyid:%s' % root_keyid,
        'aki': x509.AuthorityKeyIdentifier(
            key_identifier=b'y&\x89\xd2]\xd8\xe1,1q\xef\xad8\xb4\xb6)\xf17(G',
            authority_cert_issuer=None, authority_cert_serial_number=None
        ),
        'hpkp': 'MWvvGs9cF37mKmi2iXqBBqpkBT8zaWfT09DRSlpg8tQ=',
        'crl': None,
        'subjectKeyIdentifier': root_keyid,
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
        'serial': '32:82:9C:62:71:0B:74:62:32:33:75:FF:CC:1C:42:2F:73:BE:61:37',
        'md5': '63:C1:A3:28:B4:01:80:A3:96:22:23:96:57:17:98:7D',
        'sha1': '98:10:30:97:99:DB:85:29:74:E6:D0:5E:EE:C8:C5:B7:06:BA:D1:19',
        'sha256': 'DA:0B:C6:6A:60:79:70:94:E1:D2:BE:68:F4:E8:FD:02:80:2A:A9:DF:85:52:49:5F:99:31:DA:15:D7:BF:BA:2E',  # NOQA
        'sha512': '12:33:63:35:91:95:69:58:B5:D0:44:1F:12:C4:40:FD:08:21:86:53:E5:05:9D:C5:49:EC:59:B5:27:63:21:AE:52:F5:BD:AA:B9:BB:F4:A1:42:BD:71:48:5B:7D:1D:0A:54:BD:2A:1F:C4:70:C5:F7:57:94:19:A8:C6:DB:B3:9D', # NOQA
        'san': None,
        'authKeyIdentifier': 'keyid:%s' % root_keyid,
        'hpkp': '+6YcoRI+EBfxBOMXlsUBKg7DexUf0AOMS08O+P+1YjI=',
        'crl': (False, ['Full Name: URI:http://parent.example.com/parent.crl']),
        'dn': '/C=AT/ST=Vienna/L=Vienna/O=example/OU=example/CN=sub.ca.example.com',
        'subjectKeyIdentifier': '8B:06:F1:9E:BC:A9:62:00:01:66:46:85:FA:90:FB:52:71:8F:66:EE',
        'keyUsage': (True, ['cRLSign', 'keyCertSign']),
        'basicConstraints': (True, 'CA:TRUE, pathlen:0'),
        'expires': datetime(2020, 12, 20, 22, 11),
        'valid_from': datetime(2018, 12, 20, 22, 11),
        'authInfoAccess': (False, ['URI:http://parent.example.com/parent.crt',
                                   'URI:http://parent.example.com/ocsp', ]),
        'aki': x509.AuthorityKeyIdentifier(
            key_identifier=b'\x8b\x06\xf1\x9e\xbc\xa9b\x00\x01fF\x85\xfa\x90\xfbRq\x8ff\xee',
            authority_cert_issuer=None, authority_cert_serial_number=None
        ),
        'name_constraints': NameConstraints([['DNS:.net'], ['DNS:.org']]),
    },
    'ecc_ca': {
        'name': 'ecc_ca',
        'serial': '52:F4:84:51:D7:38:D9:E6:83:43:7A:4A:1D:EB:ED:A0:7D:6A:7F:D9',
        'aki': x509.AuthorityKeyIdentifier(
            key_identifier=b")TaW\xa9\xcdu\xdd\x19\x0f]\x8bs\x13'/\xde\xc1\xf1\x04",
            authority_cert_issuer=None, authority_cert_serial_number=None
        ),
    },
    'pwd_ca': {
        'name': 'pwd_ca',
        'serial': '61:0A:D4:09:CE:18:6A:12:D6:69:F2:68:7D:4D:1A:7C:E9:89:02:62',
        'aki': x509.AuthorityKeyIdentifier(
            key_identifier=b'\x8a\x9a\r\xa7\xbc\xc7\x0bcY\xc8\xcb\r\x87Nvm\xc3\xe8H\x15',
            authority_cert_issuer=None, authority_cert_serial_number=None
        ),
    },
    'cert1': {
        'pem': force_text(cert1_pem),
        'hpkp': 'ZHsPuAAhLPHXbSjBW8/2/CylrtpcPlNUcLDMmuMtiWY=',
        'md5': '7B:42:32:BB:7F:C1:E5:CE:3C:ED:1B:74:2F:36:4B:44',
        'sha1': '69:CA:37:7F:82:E5:6E:D9:7B:5A:72:60:F8:94:C6:2B:99:C1:2D:EA',
        'sha256': '88:99:CB:BE:D8:31:9F:76:08:4F:13:03:98:96:81:8D:35:92:E4:11:0D:72:62:F6:00:B9:1A:0F:CB:8B:60:1B',  # NOQA
        'sha512': '51:9E:A7:43:8D:9A:E4:E0:AA:94:C0:4E:60:7F:5E:42:CD:03:E1:E9:D3:93:CB:A6:70:C1:D8:F2:D4:31:F3:A2:F3:17:D6:73:90:DC:66:F3:0F:65:FD:46:BB:BB:FA:1E:AC:D9:FC:D4:80:9F:38:A3:47:71:28:CD:DD:C2:32:F1', # NOQA
        'san': SubjectAlternativeName('DNS:host1.example.com'),
        'cn': 'host1.example.com',
        'keyUsage': (True, ['digitalSignature', 'keyAgreement', 'keyEncipherment']),
        'from': '2017-04-17 11:47',
        'until': '2019-04-18 00:00',
        'status': 'Valid',
        'subjectKeyIdentifier': 'D2:1B:D1:90:35:0E:44:58:F7:0A:21:BB:DC:BE:3D:7F:ED:83:E4:FA',
        'authKeyIdentifier': 'keyid:%s' % root_keyid,
        'issuer_alternative_name': 'URI:https://ca.example.com',
        'authInfoAccess': (False, ['URI:http://ca.example.com/ca.crt',
                                   'URI:http://ocsp.ca.example.com', ]),
        'crl': (False, ['Full Name: URI:http://ca.example.com/crl']),
        'der': cert1_pubkey.public_bytes(encoding=Encoding.DER),
        'serial': '5A:1B:A2:63:A1:E4:D8:D1:4D:82:60:46:D3:8F:E0:C3:A5:B3:E4:89',
        'expires': datetime(2019, 4, 18, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
    'cert2': {
        'issuer_alternative_name': 'URI:https://ca.example.com',
        'md5': '4B:1C:B9:1E:34:B3:E0:7A:F9:95:E4:92:94:54:19:6B',
        'sha1': '3B:EB:92:1C:99:0D:E9:C6:57:2E:ED:A0:25:00:84:21:9E:37:25:87',
        'sha256': 'A2:18:2B:7E:5D:A3:A8:64:B4:9B:74:D5:4A:FB:46:60:DC:B7:A5:20:ED:0E:0E:EC:7A:2E:20:01:20:E9:3F:4C',  # NOQA
        'sha512': '63:86:08:13:70:6E:A2:C3:95:2B:E6:33:16:D8:1C:6E:48:FA:7B:73:6D:51:D0:98:AD:7D:F3:9F:79:5C:03:A0:21:23:DA:88:5C:DD:BB:03:86:E0:A8:77:C3:36:46:06:E9:AA:0C:02:A5:56:81:2B:04:1A:37:11:2A:DE:A2:A5', # NOQA
        'san': SubjectAlternativeName('DNS:host2.example.com'),
        'authKeyIdentifier': 'keyid:%s' % root_keyid,
        'hpkp': 'i+ccTaizbK5r9luNHFW358cxzaORJ4rS3WYHlEnaQoI=',
        'crl': (False, ['Full Name: URI:http://ca.example.com/crl']),
        'serial': '4E:2B:01:C4:8B:CC:1F:71:94:12:88:64:68:0C:AA:04:D3:F8:BB:45',
        'expires': datetime(2019, 4, 18, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },
    'cert3': {
        'issuer_alternative_name': 'URI:https://ca.example.com',
        'md5': '43:47:4B:6D:7C:7E:3A:BB:85:AF:0F:2E:70:2B:12:07',
        'sha1': '28:65:FB:33:4E:60:DD:44:22:5D:5F:61:FF:C0:6C:FB:3F:23:55:87',
        'sha256': '2A:18:6B:D9:B4:A9:B7:12:17:41:20:A6:6C:D4:AA:0D:D7:98:A0:5F:53:26:C7:47:AA:00:A4:2C:DF:7A:07:96',  # NOQA
        'sha512': 'B2:E8:35:D7:56:37:DA:76:B7:F7:94:5C:A5:66:A7:6E:CC:A7:18:26:35:DC:1C:AD:AC:27:56:83:CA:4E:FD:66:4B:E9:89:6E:D5:A1:7D:94:94:0B:9B:35:E3:45:B5:78:AD:50:8F:CF:5C:9B:1E:16:70:54:B7:76:C4:86:30:66', # NOQA
        'san': SubjectAlternativeName('DNS:host3.example.com'),
        'authKeyIdentifier': 'keyid:%s' % root_keyid,
        'hpkp': 'ZuJoB0pw8rd2os1WFVe5f8Vky6eg3vHxCrnaZxupFQo=',
        'crl': (False, ['Full Name: URI:http://ca.example.com/crl']),
        'serial': '32:A7:B0:8E:88:A2:1A:EC:05:C8:BA:18:D7:8B:D9:35:45:9D:82:FA',
        'expires': datetime(2019, 4, 18, 0, 0),
        'valid_from': datetime(2017, 4, 17, 11, 47),
    },

    # created using django_ca.tests.tests_managers.GetCertTestCase.test_all_extensions
    'cert_all': {
        'cn': 'all-extensions.example.com',
        'crl': (False, ['Full Name: URI:%s' % root_crl_url]),
        'from': '2018-10-26 00:00',
        'hpkp': 'y7MP7lTrd5tT5cf7dO/ikFaoj/YmJFke2MAIr5uJf74=',
        'serial': '49:BC:F2:FE:FA:31:03:B6:E0:CC:3D:16:93:4E:2D:B0:8A:D2:C5:87',
        'status': 'Valid',
        'until': '2020-10-16 00:00',
        'md5': '98:50:F0:6E:1F:AF:36:82:85:8C:06:04:65:27:B1:6F',
        'sha1': 'CE:36:78:D4:1E:06:43:B2:F2:A1:F7:BA:1F:9C:A8:60:0B:F0:EB:57',
        'sha256': '79:EA:A9:31:21:01:80:1C:0B:05:7E:BE:56:84:D8:E9:C9:0B:63:92:52:AE:1D:A8:78:20:55:52:CF:74:A7:9F',  # NOQA
        'sha512': 'CE:FE:17:4F:0B:58:82:7C:50:21:BE:11:1E:15:F3:AA:94:A7:ED:D0:37:AC:8B:E3:95:13:BE:69:0D:EA:83:AD:B1:06:A6:6E:F0:05:CD:8B:BF:61:1A:DF:5A:03:7E:34:05:71:73:BC:94:0B:7F:6C:CA:1A:88:92:A5:60:94:8E',  # NOQA
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
        'subject_key_identifier': SubjectKeyIdentifier('DE:EA:38:FC:DA:39:92:33:45:A7:B9:F8:D2:DF:84:0E:CC:6F:3A:B9'),  # NOQA
        'tls_feature': TLSFeature('critical,OCSPMustStaple,MultipleCertStatusRequest'),
    },
    'ocsp': {
        'cn': root_ocsp_domain,
        'crl': (False, ['Full Name: URI:%s' % root_crl_url]),
        'expires': datetime(2020, 10, 16, 0, 0),
        'from': '2018-10-26 00:00',
        'hpkp': 'ZdNmzaYDup9ws7OGII3V0SGv0T0AlockXgnQz0GOEd4=',
        'serial': '4E:A5:A0:D1:19:21:2E:AB:3D:56:39:FA:BD:D0:A7:5B:CC:35:E4:D9',
        'status': 'Valid',
        'until': '2020-10-16 00:00',
        'valid_from': datetime(2018, 10, 26, 0, 0),
        'md5': 'A6:C7:2C:8E:10:89:3D:CC:CB:D8:19:8A:46:10:8B:6F',
        'sha1': 'DC:EA:6B:E9:EB:A7:BA:AA:B2:1D:F9:4F:E2:A3:1C:6A:C2:A5:15:3A',
        'sha256': '9D:16:D6:7F:F1:CF:3C:59:4A:F0:19:CF:24:16:00:A0:34:9D:0C:03:17:37:7B:EC:AE:E3:67:4E:2B:80:49:D2',  # NOQA
        'sha512': '0A:CE:5C:21:13:4C:CC:2F:0F:BF:CE:5F:0E:82:53:2F:8E:26:50:9E:24:28:AD:33:71:D7:83:08:0B:B4:1A:CE:9B:EF:0E:E0:0B:56:30:9F:75:AC:F7:FC:7B:BC:65:B4:AA:A5:42:4C:D3:0D:9F:ED:3E:76:34:AD:89:1A:56:1E',  # NOQA
        'sha512': '0F:5D:47:AF:BD:36:8F:07:42:D3:45:8B:80:80:7C:B6:7A:95:83:36:34:6E:B5:EA:1D:86:40:98:B0:99:FF:CF:C7:ED:33:D7:F7:D4:FB:16:86:45:DB:42:FA:97:CA:16:F9:91:07:8D:2D:10:B2:81:AC:44:2D:D6:2F:56:1B:4A',  # NOQA
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
        'subject_key_identifier': SubjectKeyIdentifier('31:CB:89:87:60:8D:AB:3B:92:93:A3:F1:4E:0F:D7:E5:07:62:35:CC'),  # NOQA
    },

    # contrib certificates
    'cloudflare_1': {
        'cn': 'sni24142.cloudflaressl.com',
        'precert_poison': True,  # only set once we require cryptography>=2.4
        'md5': 'D6:76:03:E9:4F:3B:B0:F1:F7:E3:A1:40:80:8E:F0:4A',
        'sha1': '71:BD:B8:21:80:BD:86:E8:E5:F4:2B:6D:96:82:B2:EF:19:53:ED:D3',
        'sha256': '1D:8E:D5:41:E5:FF:19:70:6F:65:86:A9:A3:6F:DF:DE:F8:A0:07:22:92:71:9E:F1:CD:F8:28:37:39:02:E0:A1',  # NOQA
        'sha512': 'FF:03:1B:8F:11:E8:A7:FF:91:4F:B9:97:E9:97:BC:77:37:C1:A7:69:86:F3:7C:E3:BB:BB:DF:A6:4F:0E:3C:C0:7F:B5:BC:CC:BD:0A:D5:EF:5F:94:55:E9:FF:48:41:34:B8:11:54:57:DD:90:85:41:2E:71:70:5E:FA:BA:E6:EA',  # NOQA
        'hpkp': 'bkunFfRSda4Yhz7UlMUaalgj0Gcus/9uGVp19Hceczg=',
    },
}

if ca_settings.CRYPTOGRAPHY_HAS_PRECERT_POISON:  # pragma: no branch, pragma: only cryptography>=2.4
    certs['cert_all']['precert_poison'] = PrecertPoison()
    certs['cloudflare_1']['precert_poison'] = PrecertPoison()


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

        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'root.key'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'root-key.der'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'root-pub.der'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'child.key'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'ocsp.key'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'ocsp.pem'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'pwd_ca.key'), self.options['CA_DIR'])
        shutil.copy(os.path.join(settings.FIXTURES_DIR, 'ecc_ca.key'), self.options['CA_DIR'])

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
                  extensions=None):
        certs = certs or []
        signer = signer or self.ca
        algorithm = algorithm or ca_settings.CA_DIGEST_ALGORITHM
        extensions = extensions or []
        expires = datetime.utcnow() + timedelta(seconds=expires)

        if encoding == Encoding.PEM:
            crl = x509.load_pem_x509_crl(crl, default_backend())
        else:
            crl = x509.load_der_x509_crl(crl, default_backend())

        self.assertIsInstance(crl.signature_hash_algorithm, type(algorithm))
        self.assertTrue(crl.is_signature_valid(signer.x509.public_key()))
        self.assertEqual(crl.issuer, signer.x509.subject)
        self.assertEqual(crl.last_update, datetime.utcnow())
        self.assertEqual(crl.next_update, expires)
        self.assertEqual(list(crl.extensions), extensions)

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

        kwargs['script'] = sys.argv[0]
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
        for elem in chain:
            store.add_cert(load_certificate(FILETYPE_PEM, elem.dump_certificate()))

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
            elif isinstance(value, Extension):
                ctx[key] = value
                ctx['%s_text' % key] = value.as_text()
                if value.critical:
                    ctx['%s_critical' % key] = ' (critical)'
                else:
                    ctx['%s_critical' % key] = ''
            else:
                ctx[key] = value

        return ctx

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
        self.ca = self.load_ca(name='root', x509=root_pubkey)
        self.pwd_ca = self.load_ca(name='pwd_ca', x509=pwd_ca_pubkey)
        self.ecc_ca = self.load_ca(name='ecc_ca', x509=ecc_ca_pubkey)
        self.cas = [self.ca, self.pwd_ca, self.ecc_ca]


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
        self.cert2 = self.load_cert(self.ca, cert2_pubkey)
        self.cert3 = self.load_cert(self.ca, cert3_pubkey)
        self.ocsp = self.load_cert(self.ca, ocsp_pubkey)
        self.cert_all = self.load_cert(self.ca, x509=all_pubkey, csr=all_csr)
        self.cert_no_ext = self.load_cert(self.ca, x509=no_ext_pubkey, csr=no_ext_csr)

        # the one with no hostname:
        self.cert_multiple_ous_and_no_ext = self.load_cert(self.ca, multiple_ous_and_no_ext_pubkey)

        self.cert_cloudflare_1 = self.load_cert(self.ca, cloudflare_1_pubkey)
        self.cert_letsencrypt_jabber_at = self.load_cert(self.ca, letsencrypt_jabber_at_pubkey)
        self.cert_godaddy_derstandardat = self.load_cert(self.ca, godaddy_derstandardat_pubkey)

        self.certs = [
            self.cert, self.cert2, self.cert3, self.ocsp, self.cert_all, self.cert_no_ext,
            self.cert_multiple_ous_and_no_ext, self.cert_cloudflare_1, self.cert_letsencrypt_jabber_at,
            self.cert_godaddy_derstandardat,
        ]


class DjangoCAWithChildCATestCase(DjangoCAWithCertTestCase):
    def setUp(self):
        super(DjangoCAWithChildCATestCase, self).setUp()
        self.child_ca = self.load_ca(name='child', x509=child_pubkey, parent=self.ca)
        self.cas.append(self.child_ca)
