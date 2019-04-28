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

from .base import DjangoCAWithCATestCase
from .base import override_settings
from .base import override_tmpcadir

# Root CAs with no children can always use the same template (since they all use the same extensions)
root_expected = '''{name} (enabled):
* Serial: {serial}
* Path to private key:
  {key_path}
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pem}'''


class ViewCATestCase(DjangoCAWithCATestCase):
    @override_tmpcadir()
    def test_ca(self):
        stdout, stderr = self.cmd('view_ca', self.ca.serial)
        data = self.get_cert_context('root')
        self.assertMultiLineEqual(stdout, '''{name} (enabled):
* Serial: {serial}
* Path to private key:
  {key_path}
* Is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pem}'''.format(**data))
        self.assertEqual(stderr, '')

    @override_tmpcadir()
    def test_child(self):
        stdout, stderr = self.cmd('view_ca', self.child_ca.serial)
        data = self.get_cert_context('child')
        self.assertMultiLineEqual(stdout, '''{name} (enabled):
* Serial: {serial}
* Path to private key:
  {key_path}
* Parent: {parent_name} ({parent_serial})
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityInfoAccess{authority_information_access_critical}:
    CA Issuers:
      * URI:{authority_information_access.issuers[0].value}
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
cRLDistributionPoints:
    * Full Name: URI:{crl}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pem}'''.format(**data))
        self.assertEqual(stderr, '')

    @override_tmpcadir()
    def test_ecc(self):
        stdout, stderr = self.cmd('view_ca', self.ecc_ca.serial)
        data = self.get_cert_context('ecc')
        self.assertMultiLineEqual(stdout, root_expected.format(**data))
        self.assertEqual(stderr, '')

    @override_tmpcadir()
    def test_pwd(self):
        stdout, stderr = self.cmd('view_ca', self.pwd_ca.serial)
        data = self.get_cert_context('pwd')
        self.assertMultiLineEqual(stdout, root_expected.format(**data))
        self.assertEqual(stderr, '')

    @override_tmpcadir()
    def test_dsa(self):
        stdout, stderr = self.cmd('view_ca', self.dsa_ca.serial)
        data = self.get_cert_context('dsa')
        self.assertMultiLineEqual(stdout, root_expected.format(**data))
        self.assertEqual(stderr, '')


@override_settings(USE_TZ=True)
class ViewCAWithTZTestCase(ViewCATestCase):
    pass
