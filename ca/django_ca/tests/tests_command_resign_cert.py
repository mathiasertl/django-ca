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
# see <http://www.gnu.org/licenses/>

import os

from django.utils import six

from .. import ca_settings
from ..extensions import BasicConstraints
from ..extensions import ExtendedKeyUsage
from ..extensions import KeyUsage
from ..extensions import SubjectAlternativeName
from ..extensions import TLSFeature
from ..models import Certificate
from ..models import Watcher
from ..signals import post_issue_cert
from ..signals import pre_issue_cert
from ..subject import Subject
from .base import DjangoCAWithCertTestCase
from .base import override_tmpcadir

if six.PY2:  # pragma: only py2
    from mock import patch
else:  # pragma: only py3
    from unittest.mock import patch


class ResignCertTestCase(DjangoCAWithCertTestCase):
    def assertResigned(self, old, new):
        self.assertNotEqual(old.pk, new.pk)  # make sure we're not comparing the same cert

        # assert various properties
        self.assertEqual(old.algorithm, new.algorithm)
        self.assertEqual(old.issuer, new.issuer)
        self.assertEqual(old.hpkp_pin, new.hpkp_pin)

    def assertEqualExt(self, old, new):
        self.assertEqual(old.subject, new.subject)

        # assert extensions that should be equal
        self.assertEqual(old.authority_key_identifier, new.authority_key_identifier)
        self.assertEqual(old.extended_key_usage, new.extended_key_usage)
        self.assertEqual(old.key_usage, new.key_usage)
        self.assertEqual(old.subject_alternative_name, new.subject_alternative_name)
        self.assertEqual(old.tls_feature, new.tls_feature)

        # Test extensions that don't come from the old cert but from the signing CA
        self.assertEqual(new.basic_constraints, BasicConstraints('critical,false'))
        self.assertIsNone(new.issuer_alternative_name)  # signing ca does not have this set

        # Some properties come from the ca
        self.assertEqual(old.ca.crl_url, new.crlDistributionPoints())

    def test_basic(self):
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('resign_cert', self.cert.serial)
        self.assertEqual(stderr, '')
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    def test_overwrite(self):
        key_usage = 'cRLSign'
        ext_key_usage = 'critical,emailProtection'
        tls_feature = 'critical,MultipleCertStatusRequest'
        subject = '/CN=new.example.com'
        watcher = 'new@example.com'
        alt = 'new-alt-name.example.com'

        # resign a cert, but overwrite all options
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd_e2e([
                'resign_cert', self.cert.serial,
                '--key-usage', key_usage,
                '--ext-key-usage', ext_key_usage,
                '--tls-feature', tls_feature,
                '--subject', subject,
                '--watch', watcher,
                '--alt', alt,
            ])
        self.assertEqual(stderr, '')
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        new = Certificate.objects.get(pub=stdout)
        self.assertResigned(self.cert, new)

        # assert overwritten extensions
        self.assertEqual(new.subject, Subject(subject))
        self.assertEqual(new.subject_alternative_name, SubjectAlternativeName('DNS:%s' % alt))
        self.assertEqual(new.key_usage, KeyUsage(key_usage))
        self.assertEqual(new.extended_key_usage, ExtendedKeyUsage(ext_key_usage))
        self.assertEqual(new.tls_feature, TLSFeature(tls_feature))
        self.assertEqual(list(new.watchers.all()), [Watcher.objects.get(mail=watcher)])

    @override_tmpcadir()
    def test_to_file(self):
        out_path = os.path.join(ca_settings.CA_DIR, 'test.pem')

        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post:
            stdout, stderr = self.cmd('resign_cert', self.cert.serial, out=out_path)
        self.assertEqual(stderr, '')
        self.assertEqual(pre.call_count, 1)
        self.assertEqual(post.call_count, 1)

        with open(out_path) as stream:
            pub = stream.read()

        new = Certificate.objects.get(pub=pub)
        self.assertResigned(self.cert, new)
        self.assertEqualExt(self.cert, new)

    def test_no_cn(self):
        subject = '/C=AT'  # has no CN

        msg = r'^Must give at least a CN in --subject or one or more --alt arguments\.'
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post, \
                self.assertCommandError(msg):
            self.cmd('resign_cert', self.cert_no_ext.serial, subject=Subject(subject))

        # signals not called
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)

    def test_error(self):
        msg = 'foobar'
        msg_re = r'^%s$' % msg
        with self.assertSignal(pre_issue_cert) as pre, self.assertSignal(post_issue_cert) as post, \
                patch('django_ca.managers.CertificateManager.init', side_effect=Exception(msg)), \
                self.assertCommandError(msg_re):

            self.cmd('resign_cert', self.cert.serial)

        # signals not called
        self.assertEqual(pre.call_count, 0)
        self.assertEqual(post.call_count, 0)
