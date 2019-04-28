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

import json
import os
import shutil
import subprocess
import sys
import tempfile

#from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
#from cryptography.hazmat.primitives.serialization import Encoding
#from cryptography.hazmat.primitives.serialization import NoEncryption
#from cryptography.hazmat.primitives.serialization import PrivateFormat
_rootdir = os.path.dirname(os.path.realpath(__file__))  # NOQA
sys.path.insert(0, os.path.join(_rootdir, 'ca'))  # NOQA
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'ca.test_settings')  # NOQA
import django  # NOQA
django.setup()  # NOQA

from django.conf import settings
from django.core.management import call_command as manage
from django.test.utils import override_settings
from django.utils.six.moves import reload_module
from django.urls import reverse

from django_ca import ca_settings
from django_ca.models import Certificate
from django_ca.models import CertificateAuthority
from django_ca.profiles import get_cert_profile_kwargs
from django_ca.utils import bytes_to_hex
from django_ca.utils import ca_storage

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3
if PY2:  # pragma: only py2
    from mock import patch
else:
    from unittest.mock import patch

manage('migrate', verbosity=0)

# Some variables used in various places throughout the code
key_size = 1024  # Size for private keys
ca_base_cn = 'ca.example.com'
child_pathlen = 0
ecc_pathlen = 1
pwd_pathlen = 2
dsa_pathlen = 3
dsa_algorithm = 'SHA1'
testserver = 'http://testserver'


class override_tmpcadir(override_settings):
    """Simplified copy of the same decorator in tests.base."""

    def enable(self):
        self.options['CA_DIR'] = tempfile.mkdtemp()
        self.mock = patch.object(ca_storage, 'location', self.options['CA_DIR'])
        self.mock_ = patch.object(ca_storage, '_location', self.options['CA_DIR'])
        self.mock.start()
        self.mock_.start()

        super(override_tmpcadir, self).enable()
        reload_module(ca_settings)

    def disable(self):
        super(override_tmpcadir, self).disable()
        self.mock.stop()
        self.mock_.stop()
        shutil.rmtree(self.options['CA_DIR'])
        reload_module(ca_settings)


def update_cert_data(cert, data):
    data['serial'] = cert.serial
    data['hpkp'] = cert.hpkp_pin
    data['authority_key_identifier'] = bytes_to_hex(cert.authority_key_identifier.value)
    data['subject_key_identifier'] = bytes_to_hex(cert.subject_key_identifier.value)
    data['valid_from'] = cert.x509.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
    data['valid_until'] = cert.x509.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')

    data['md5'] = cert.get_digest('md5')
    data['sha1'] = cert.get_digest('sha1')
    data['sha256'] = cert.get_digest('sha256')
    data['sha512'] = cert.get_digest('sha512')

    ku = cert.key_usage
    if ku is not None:
        data['key_usage'] = ku.serialize()

    aia = cert.authority_information_access
    if aia is not None:
        data['authority_information_access'] = aia.serialize()


def write_ca(cert, data, password=None):
    key_dest = os.path.join(settings.FIXTURES_DIR, data['key'])
    pub_dest = os.path.join(settings.FIXTURES_DIR, data['pub'])
    #key_der_dest = os.path.join(settings.FIXTURES_DIR, data['key-der'])
    #pub_der_dest = os.path.join(settings.FIXTURES_DIR, data['pub-der'])

    # write files to dest
    shutil.copy(ca_storage.path(cert.private_key_path), key_dest)
    with open(pub_dest, 'w') as stream:
        stream.write(cert.pub)

    #if password is None:
    #    encryption = NoEncryption()
    #else:
    #    encryption = BestAvailableEncryption(password)

    #key_der = cert.key(password=password).private_bytes(
    #   encoding=Encoding.DER, format=PrivateFormat.PKCS8, encryption_algorithm=encryption)
    #with open(key_der_dest, 'wb') as stream:
    #    stream.write(key_der)
    #with open(pub_der_dest, 'wb') as stream:
    #    stream.write(cert.dump_certificate(Encoding.DER))

    update_cert_data(cert, data)


def copy_cert(cert, data, key_path, csr_path):
    key_dest = os.path.join(settings.FIXTURES_DIR, data['key'])
    csr_dest = os.path.join(settings.FIXTURES_DIR, data['csr'])
    pub_dest = os.path.join(settings.FIXTURES_DIR, data['pub'])
    shutil.copy(key_path, key_dest)
    shutil.copy(csr_path, csr_dest)
    with open(pub_dest, 'w') as stream:
        stream.write(cert.pub)

    update_cert_data(cert, data)


data = {
    'root': {
        'password': None,
        'subject': '/C=AT/ST=Vienna/CN=%s' % ca_base_cn,
        'pathlen': None,

        'basic_constraints': 'critical,CA:TRUE',
        'key_usage': 'critical,cRLSign,keyCertSign',
    },
    'child': {
        'password': None,
        'subject': '/C=AT/ST=Vienna/CN=child.%s' % ca_base_cn,

        'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % child_pathlen,
        'pathlen': child_pathlen,
        'name_constraints': [['DNS:.org'], ['DNS:.net']],
    },
    'ecc': {
        'password': None,
        'subject': '/C=AT/ST=Vienna/CN=ecc.%s' % ca_base_cn,

        'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % ecc_pathlen,
        'pathlen': ecc_pathlen,
    },
    'dsa': {
        'algorithm': dsa_algorithm,
        'password': None,
        'subject': '/C=AT/ST=Vienna/CN=dsa.%s' % ca_base_cn,

        'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % dsa_pathlen,
        'pathlen': dsa_pathlen,
    },
    'pwd': {
        'password': 'testpassword',
        'subject': '/C=AT/ST=Vienna/CN=pwd.%s' % ca_base_cn,

        'basic_constraints': 'critical,CA:TRUE,pathlen=%s' % pwd_pathlen,
        'pathlen': pwd_pathlen,
    },

    'root-cert': {
        'ca': 'root',
        'csr': True,
    },
    'child-cert': {
        'ca': 'child',
        'csr': True,
    },
    'ecc-cert': {
        'ca': 'ecc',
        'csr': True,
    },
    'pwd-cert': {
        'ca': 'pwd',
        'csr': True,
    },
    'dsa-cert': {
        'ca': 'dsa',
        'algorithm': dsa_algorithm,
        'csr': True,
    },
}

# Autocompute some values (name, filenames, ...) based on the dict key
for cert, cert_values in data.items():
    cert_values['name'] = cert
    cert_values.setdefault('algorithm', 'SHA256')
    cert_values['key'] = '%s.key' % cert_values['name']
    cert_values['pub'] = '%s.pem' % cert_values['name']
    if cert_values.pop('csr', False):
        cert_values['csr'] = '%s.csr' % cert_values['name']

data['root']['issuer'] = data['root']['subject']
data['root']['issuer_url'] = '%s/%s.der' % (testserver, data['root']['name'])
data['root']['ocsp_url'] = '%s/ocsp/%s/' % (testserver, data['root']['name'])
data['child']['issuer'] = data['root']['subject']
data['child']['crl'] = '%s/%s.crl' % (testserver, data['root']['name'])

with override_tmpcadir():
    # Create CAs
    root = CertificateAuthority.objects.init(
        name=data['root']['name'], subject=data['root']['subject'], key_size=key_size,
    )
    root.crl_url = '%s%s' % (testserver, reverse('django_ca:crl', kwargs={'serial': root.serial}))
    root_ca_crl = '%s%s' % (testserver, reverse('django_ca:ca-crl', kwargs={'serial': root.serial}))
    root.save()
    write_ca(root, data['root'])

    child = CertificateAuthority.objects.init(
        name=data['child']['name'], subject=data['child']['subject'], parent=root, key_size=key_size,
        pathlen=child_pathlen, ca_crl_url=root_ca_crl, ca_issuer_url=data['root']['issuer_url'],
        ca_ocsp_url=data['root']['ocsp_url']
    )
    data['child']['crl'] = root_ca_crl
    write_ca(child, data['child'])

    dsa = CertificateAuthority.objects.init(
        name=data['dsa']['name'], subject=data['dsa']['subject'], key_size=key_size,
        pathlen=dsa_pathlen, key_type='DSA', algorithm=data['dsa']['algorithm'],
    )
    write_ca(dsa, data['dsa'])

    ecc = CertificateAuthority.objects.init(
        name=data['ecc']['name'], subject=data['ecc']['subject'], key_size=key_size, key_type='ECC',
        pathlen=ecc_pathlen
    )
    write_ca(ecc, data['ecc'])

    pwd_password = data['pwd']['password'].encode('utf-8')
    pwd = CertificateAuthority.objects.init(
        name=data['pwd']['name'], subject=data['pwd']['subject'], key_size=key_size, password=pwd_password,
        pathlen=pwd_pathlen
    )
    write_ca(pwd, data['pwd'], password=pwd_password)

    # add parent/child relationships
    data['root']['children'] = [
        [data['child']['name'], data['child']['serial']],
    ]
    data['child']['parent'] = [data['root']['name'], data['root']['serial']]

    # let's create a standard certificate for every CA
    for ca in [root, child, dsa, ecc, pwd]:
        name = '%s-cert' % ca.name
        key_path = os.path.join(ca_settings.CA_DIR, '%s.key' % name)
        csr_path = os.path.join(ca_settings.CA_DIR, '%s.csr' % name)
        common_name = '%s.example.com' % name

        if PY2:
            # PY2 does not have subprocess.DEVNULL
            with open(os.devnull, 'w') as devnull:
                subprocess.call(['openssl', 'genrsa', '-out', key_path, str(key_size)], stderr=devnull)
        else:
            subprocess.call(['openssl', 'genrsa', '-out', key_path, str(key_size)], stderr=subprocess.DEVNULL)

        subprocess.call(['openssl', 'req', '-new', '-key', key_path, '-out', csr_path, '-utf8', '-batch'])
        kwargs = get_cert_profile_kwargs('server')
        kwargs['subject'].append(('CN', common_name))
        with open(csr_path) as stream:
            csr = stream.read()

        pwd = data[data[name]['ca']]['password']
        if pwd is not None:
            pwd = pwd.encode('utf-8')

        cert = Certificate.objects.init(ca=ca, csr=csr, algorithm=data[name]['algorithm'],
                                        password=pwd, **kwargs)
        copy_cert(cert, data[name], key_path, csr_path)

fixture_data = {
    'certs': data,
}

with open(os.path.join(settings.FIXTURES_DIR, 'cert-data.json'), 'w') as stream:
    json.dump(fixture_data, stream, indent=4)
