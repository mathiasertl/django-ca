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

from io import BytesIO

from cryptography.hazmat.primitives.serialization import Encoding

from django.utils.encoding import force_bytes

from freezegun import freeze_time

from .. import ca_settings
from ..models import Watcher
from .base import DjangoCAWithCertTestCase
from .base import certs
from .base import override_settings
from .base import override_tmpcadir
from .base import timestamps

output = {
    'root-cert': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'child-cert': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'ecc-cert': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'pwd-cert': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'dsa-cert': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'profile-client': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'profile-server': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'profile-webserver': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'profile-enduser': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
    * {extended_key_usage_2}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'profile-ocsp': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'no-extensions': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'all-extensions': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
    * {extended_key_usage_2}
    * {extended_key_usage_3}
IssuerAlternativeName{issuer_alternative_name_critical}:
    * {issuer_alternative_name[0]}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
NameConstraints{name_constraints_critical}:
    Permitted:
      * DNS:{name_constraints.permitted[0].value}
    Excluded:
      * DNS:{name_constraints.excluded[0].value}
OCSPNoCheck{ocsp_no_check_critical}: Yes
{precert_poison}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
TLSFeature{tls_feature_critical}:
    * {tls_feature_0}
    * {tls_feature_1}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',

    'alt-extensions': '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl_distribution_points[0].full_name[0].value}
    * DistributionPoint:
      * Relative Name: /CN=rdn.ca.example.com
      * CRL Issuer:
        * URI:{crl_distribution_points[1].crl_issuer[0].value}
        * URI:{crl_distribution_points[1].crl_issuer[1].value}
      * Reasons: ca_compromise, key_compromise
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
    * {extended_key_usage_2}
    * {extended_key_usage_3}
IssuerAlternativeName{issuer_alternative_name_critical}:
    * {issuer_alternative_name[0]}
    * {issuer_alternative_name[1]}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
NameConstraints{name_constraints_critical}:
    Permitted:
      * DNS:{name_constraints.permitted[0].value}
OCSPNoCheck{ocsp_no_check_critical}: Yes
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name[0]}
    * {subject_alternative_name[1]}
    * {subject_alternative_name[2]}
    * {subject_alternative_name[3]}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
TLSFeature{tls_feature_critical}:
    * {tls_feature_0}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''',
}


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={})
class ViewCertTestCase(DjangoCAWithCertTestCase):
    def _get_format(self, cert):
        return {
            'cn': cert.cn,
            'from': cert.not_before.strftime('%Y-%m-%d %H:%M'),
            'until': cert.not_after.strftime('%Y-%m-%d %H:%M'),
            'pub': cert.pub,
            'md5': cert.get_digest('md5'),
            'sha1': cert.get_digest('sha1'),
            'sha256': cert.get_digest('sha256'),
            'sha512': cert.get_digest('sha512'),
            'subjectKeyIdentifier': cert.subject_key_identifier.as_text(),
            'authorityKeyIdentifier': cert.ca.subject_key_identifier.as_text(),
            'hpkp': cert.hpkp_pin,
            'san': cert.subject_alternative_name,
        }

    def assertBasic(self, status):
        for key, cert in self.ca_certs.items():
            stdout, stderr = self.cmd('view_cert', cert.serial, stdout=BytesIO(), stderr=BytesIO())
            if cert.subject_alternative_name is None:
                self.assertEqual(stdout.decode('utf-8'), '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: {status}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}

{pub[pem]}'''.format(status=status, **self.get_cert_context(key)))
            elif len(cert.subject_alternative_name) != 1:
                continue  # no need to duplicate this here
            else:
                self.assertEqual(stdout.decode('utf-8'), '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: {status}
SubjectAlternativeName:
    * {subject_alternative_name_0}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}

{pub[pem]}'''.format(status=status, **self.get_cert_context(key)))
            self.assertEqual(stderr, b'')

        # test with no pem but with extensions
        for key, cert in self.ca_certs.items():
            stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, extensions=True,
                                      stdout=BytesIO(), stderr=BytesIO())
            self.assertEqual(stdout.decode('utf-8'), '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: {status}
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints (critical):
    CA:FALSE
CRLDistributionPoints{crl_distribution_points_critical}:
    * DistributionPoint:
      * Full Name:
        * URI:{crl}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
'''.format(status=status, **self.get_cert_context(key)))
            self.assertEqual(stderr, b'')

    @freeze_time(timestamps['before_everything'])
    def test_basic_not_yet_valid(self):
        self.assertBasic(status='Not yet valid')

    @freeze_time(timestamps['everything_expired'])
    def test_basic_expired(self):
        self.assertBasic(status='Expired')

    @freeze_time(timestamps['everything_valid'])
    def test_certs(self):
        for name, cert in self.generated_certs.items():
            stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, extensions=True,
                                      stdout=BytesIO(), stderr=BytesIO())
            self.assertEqual(stderr, b'')
            self.assertEqual(stdout.decode('utf-8'),
                             output[name].format(**self.get_cert_context(name)))

    @freeze_time(timestamps['everything_valid'])
    def test_der(self):
        self.maxDiff = None
        cert = self.certs['child-cert']
        stdout, stderr = self.cmd('view_cert', cert.serial, format=Encoding.DER,
                                  stdout=BytesIO(), stderr=BytesIO())
        expected = '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name[0]}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}

'''.format(**self.get_cert_context('child-cert'))
        expected = force_bytes(expected) + certs['child-cert']['pub']['der'] + b'\n'

        self.assertEqual(stdout, expected)
        self.assertEqual(stderr, b'')

    def test_revoked(self):
        cert = self.certs['child-cert']
        cert.revoked = True
        cert.save()
        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Revoked
SubjectAlternativeName:
    * DNS:{cn}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
'''.format(**certs['child-cert']))
        self.assertEqual(stderr, b'')

    @override_tmpcadir()
    def test_no_san_with_watchers(self):
        # test a cert with no subjectAltNames but with watchers.
        ca = self.cas['root']
        csr = certs['root-cert']['csr']['pem']
        cert = self.create_cert(ca, csr, [('CN', 'example.com')], cn_in_san=False)
        watcher = Watcher.from_addr('user@example.com')
        cert.watchers.add(watcher)

        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, stdout=BytesIO(), stderr=BytesIO())
        self.assertEqual(stdout.decode('utf-8'), '''Common Name: %(cn)s
Valid from: %(from)s
Valid until: %(until)s
Status: Valid
Watchers:
* user@example.com
Digest:
    md5: %(md5)s
    sha1: %(sha1)s
    sha256: %(sha256)s
    sha512: %(sha512)s
HPKP pin: %(hpkp)s
''' % self._get_format(cert))
        self.assertEqual(stderr, b'')

    def assertContrib(self, name, expected, **context):
        cert = self.certs[name]
        stdout, stderr = self.cmd('view_cert', cert.serial, no_pem=True, extensions=True,
                                  stdout=BytesIO(), stderr=BytesIO())
        context.update(self.get_cert_context(name))
        self.assertEqual(stderr, b'')
        self.assertEqual(stdout.decode('utf-8'), expected.format(**context))

    @freeze_time("2019-04-01")
    def test_contrib_godaddy_derstandardat(self):
        self.maxDiff = None
        if ca_settings.OPENSSL_SUPPORTS_SCT:
            sct = """PrecertificateSignedCertificateTimestamps:
    * Precertificate (v1):
        Timestamp: 2019-03-27 09:13:54.342000
        Log ID: a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10
    * Precertificate (v1):
        Timestamp: 2019-03-27 09:13:55.237000
        Log ID: ee4bbdb775ce60bae142691fabe19e66a30f7e5fb072d88300c47b897aa8fdcb
    * Precertificate (v1):
        Timestamp: 2019-03-27 09:13:56.485000
        Log ID: 4494652eb0eeceafc44007d8a8fe28c0dae682bed8cb31b53fd33396b5b681a8"""

        else:
            sct = '''PrecertificateSignedCertificateTimestamps:
    Could not parse extension (Requires OpenSSL 1.1.0f or later)'''

        self.assertContrib('godaddy_g2_intermediate-cert', '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
CRLDistributionPoints:
    * DistributionPoint:
      * Full Name:
        * URI:http://crl.godaddy.com/gdig2s1-1015.crl
CertificatePolicies{certificate_policies_critical}:
    * Policy Identifier: {certificate_policies_0.policy_identifier.dotted_string}
      Policy Qualifiers:
      * http://certificates.godaddy.com/repository/
    * Policy Identifier: {certificate_policies_1.policy_identifier.dotted_string}
      No Policy Qualifiers
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
{sct}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
    * {subject_alternative_name_3}
    * {subject_alternative_name_4}
    * {subject_alternative_name_5}
    * {subject_alternative_name_6}
    * {subject_alternative_name_7}
    * {subject_alternative_name_8}
    * {subject_alternative_name_9}
    * {subject_alternative_name_10}
    * {subject_alternative_name_11}
    * {subject_alternative_name_12}
    * {subject_alternative_name_13}
    * {subject_alternative_name_14}
    * {subject_alternative_name_15}
    * {subject_alternative_name_16}
    * {subject_alternative_name_17}
    * {subject_alternative_name_18}
    * {subject_alternative_name_19}
    * {subject_alternative_name_20}
    * {subject_alternative_name_21}
    * {subject_alternative_name_22}
    * {subject_alternative_name_23}
    * {subject_alternative_name_24}
    * {subject_alternative_name_25}
    * {subject_alternative_name_26}
    * {subject_alternative_name_27}
    * {subject_alternative_name_28}
    * {subject_alternative_name_29}
    * {subject_alternative_name_30}
    * {subject_alternative_name_31}
    * {subject_alternative_name_32}
    * {subject_alternative_name_33}
    * {subject_alternative_name_34}
    * {subject_alternative_name_35}
    * {subject_alternative_name_36}
    * {subject_alternative_name_37}
    * {subject_alternative_name_38}
    * {subject_alternative_name_39}
    * {subject_alternative_name_40}
    * {subject_alternative_name_41}
    * {subject_alternative_name_42}
    * {subject_alternative_name_43}
    * {subject_alternative_name_44}
    * {subject_alternative_name_45}
    * {subject_alternative_name_46}
    * {subject_alternative_name_47}
    * {subject_alternative_name_48}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''', sct=sct)

    @freeze_time("2019-07-05")
    def test_contrib_letsencrypt_jabber_at(self):
        name = 'letsencrypt_x3-cert'
        if ca_settings.OPENSSL_SUPPORTS_SCT:
            context = self.get_cert_context(name)
            sct = '''PrecertificateSignedCertificateTimestamps{sct_critical}:
    * Precertificate ({sct_values[0][version]}):
        Timestamp: {sct_values[0][timestamp]}
        Log ID: {sct_values[0][log_id]}
    * Precertificate ({sct_values[1][version]}):
        Timestamp: {sct_values[1][timestamp]}
        Log ID: {sct_values[1][log_id]}'''.format(**context)

        else:
            sct = '''PrecertificateSignedCertificateTimestamps:
    Could not parse extension (Requires OpenSSL 1.1.0f or later)'''

        self.assertContrib('letsencrypt_x3-cert', '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
CertificatePolicies{certificate_policies_critical}:
    * Policy Identifier: {certificate_policies_0.policy_identifier.dotted_string}
      No Policy Qualifiers
    * Policy Identifier: {certificate_policies_1.policy_identifier.dotted_string}
      Policy Qualifiers:
      * http://cps.letsencrypt.org
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
{sct}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
    * {subject_alternative_name_3}
    * {subject_alternative_name_4}
    * {subject_alternative_name_5}
    * {subject_alternative_name_6}
    * {subject_alternative_name_7}
    * {subject_alternative_name_8}
    * {subject_alternative_name_9}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''', sct=sct)

    @freeze_time("2018-12-01")
    def test_contrib_cloudflare_1(self):
        self.assertContrib('cloudflare_1', '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
AuthorityInformationAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
CRLDistributionPoints:
    * DistributionPoint:
      * Full Name:
        * URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl
CertificatePolicies{certificate_policies_critical}:
    * Policy Identifier: {certificate_policies_0.policy_identifier.dotted_string}
      Policy Qualifiers:
      * https://secure.comodo.com/CPS
    * Policy Identifier: {certificate_policies_1.policy_identifier.dotted_string}
      No Policy Qualifiers
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
{precert_poison}
SubjectAlternativeName{subject_alternative_name_critical}:
    * {subject_alternative_name_0}
    * {subject_alternative_name_1}
    * {subject_alternative_name_2}
    * {subject_alternative_name_3}
    * {subject_alternative_name_4}
    * {subject_alternative_name_5}
    * {subject_alternative_name_6}
    * {subject_alternative_name_7}
    * {subject_alternative_name_8}
    * {subject_alternative_name_9}
    * {subject_alternative_name_10}
    * {subject_alternative_name_11}
    * {subject_alternative_name_12}
    * {subject_alternative_name_13}
    * {subject_alternative_name_14}
    * {subject_alternative_name_15}
    * {subject_alternative_name_16}
    * {subject_alternative_name_17}
    * {subject_alternative_name_18}
    * {subject_alternative_name_19}
    * {subject_alternative_name_20}
    * {subject_alternative_name_21}
    * {subject_alternative_name_22}
    * {subject_alternative_name_23}
    * {subject_alternative_name_24}
    * {subject_alternative_name_25}
    * {subject_alternative_name_26}
    * {subject_alternative_name_27}
    * {subject_alternative_name_28}
    * {subject_alternative_name_29}
    * {subject_alternative_name_30}
    * {subject_alternative_name_31}
    * {subject_alternative_name_32}
    * {subject_alternative_name_33}
    * {subject_alternative_name_34}
    * {subject_alternative_name_35}
    * {subject_alternative_name_36}
    * {subject_alternative_name_37}
    * {subject_alternative_name_38}
    * {subject_alternative_name_39}
    * {subject_alternative_name_40}
    * {subject_alternative_name_41}
    * {subject_alternative_name_42}
    * {subject_alternative_name_43}
    * {subject_alternative_name_44}
    * {subject_alternative_name_45}
    * {subject_alternative_name_46}
    * {subject_alternative_name_47}
    * {subject_alternative_name_48}
    * {subject_alternative_name_49}
    * {subject_alternative_name_50}
    * {subject_alternative_name_51}
    * {subject_alternative_name_52}
    * {subject_alternative_name_53}
    * {subject_alternative_name_54}
    * {subject_alternative_name_55}
    * {subject_alternative_name_56}
    * {subject_alternative_name_57}
    * {subject_alternative_name_58}
    * {subject_alternative_name_59}
    * {subject_alternative_name_60}
    * {subject_alternative_name_61}
    * {subject_alternative_name_62}
    * {subject_alternative_name_63}
    * {subject_alternative_name_64}
    * {subject_alternative_name_65}
    * {subject_alternative_name_66}
    * {subject_alternative_name_67}
    * {subject_alternative_name_68}
    * {subject_alternative_name_69}
    * {subject_alternative_name_70}
    * {subject_alternative_name_71}
    * {subject_alternative_name_72}
    * {subject_alternative_name_73}
    * {subject_alternative_name_74}
    * {subject_alternative_name_75}
    * {subject_alternative_name_76}
    * {subject_alternative_name_77}
    * {subject_alternative_name_78}
    * {subject_alternative_name_79}
    * {subject_alternative_name_80}
    * {subject_alternative_name_81}
    * {subject_alternative_name_82}
    * {subject_alternative_name_83}
    * {subject_alternative_name_84}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
'''.format(**self.get_cert_context('cloudflare_1')))

    def test_contrib_multiple_ous(self):
        self.assertContrib('multiple_ous', '''Common Name: {cn}
Valid from: {valid_from_short}
Valid until: {valid_until_short}
Status: Valid
Watchers:
Digest:
    md5: {md5}
    sha1: {sha1}
    sha256: {sha256}
    sha512: {sha512}
HPKP pin: {hpkp}
''')

    def test_unknown_cert(self):
        name = 'foobar'
        with self.assertCommandError(r'^Error: %s: Certificate not found\.$' % name):
            self.cmd('view_cert', name, no_pem=True)


@override_settings(CA_MIN_KEY_SIZE=1024, CA_PROFILES={}, CA_DEFAULT_SUBJECT={}, USE_TZ=True)
class ViewCertWithTZTestCase(ViewCertTestCase):
    pass
