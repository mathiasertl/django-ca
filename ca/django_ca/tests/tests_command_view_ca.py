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

expected = {
    'ecc': '''{name} (enabled):
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

{pub[pem]}''',
    'child': '''{name} (enabled):
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

{pub[pem]}''',
    'root': '''{name} (enabled):
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

{pub[pem]}''',

    'globalsign': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
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

{pub[pem]}''',

    'digicert_ev_root': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
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
    * {key_usage_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

    'comodo': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
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

{pub[pem]}''',

    'identrust_root_1': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
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

{pub[pem]}''',

    'globalsign_r2_root': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
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
cRLDistributionPoints:
    * {crl_old[1][0]}
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

{pub[pem]}''',

    'comodo_dv': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
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
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
    * {certificatePolicies[1][1]}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

    'rapidssl_g3': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityInfoAccess{authority_information_access_critical}:
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
cRLDistributionPoints:
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
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

{pub[pem]}''',

    'geotrust': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
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
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

    'comodo_ev': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
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
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
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

{pub[pem]}''',

    'digicert_ha_intermediate': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityInfoAccess{authority_information_access_critical}:
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
cRLDistributionPoints:
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

    'dst_root_x3': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
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

{pub[pem]}''',

    'globalsign_dv': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityInfoAccess{authority_information_access_critical}:
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
cRLDistributionPoints:
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
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

{pub[pem]}''',

    'godaddy_g2_intermediate': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityInfoAccess{authority_information_access_critical}:
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
cRLDistributionPoints:
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
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

{pub[pem]}''',

    'godaddy_g2_root': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
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

{pub[pem]}''',

    'google_g3': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
* Has no children.
* Distinguished Name: {subject}
* Maximum levels of sub-CAs (pathlen): {pathlen_text}
* HPKP pin: {hpkp}

X509 v3 certificate extensions for CA:
AuthorityInfoAccess{authority_information_access_critical}:
    OCSP:
      * URI:{authority_information_access.ocsp[0].value}
AuthorityKeyIdentifier{authority_key_identifier_critical}:
    {authority_key_identifier_text}
BasicConstraints{basic_constraints_critical}:
    {basic_constraints_text}
cRLDistributionPoints:
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

    'letsencrypt_x1': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
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
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
    * {certificatePolicies[1][1]}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
NameConstraints{name_constraints_critical}:
    Excluded:
      * DNS:{name_constraints.excluded[0].value}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

    'letsencrypt_x3': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
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
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
    * {certificatePolicies[1][1]}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

    'startssl_root': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
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
certificatePolicies:
    * {certificatePolicies[1][0]}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}
UnknownOID:
    <ObjectIdentifier(oid=2.16.840.1.113730.1.1, name=Unknown OID)>
UnknownOID:
    <ObjectIdentifier(oid=2.16.840.1.113730.1.13, name=Unknown OID)>

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',
    'startssl_class2': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
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
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
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

{pub[pem]}''',

    'startssl_class3': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
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
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
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

{pub[pem]}''',

    'trustid_server_a52': '''{name} (enabled):
* Serial: {serial}
* Private key not available locally.
* Is a root CA.
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
    * {crl_old[1][0]}
certificatePolicies:
    * {certificatePolicies[1][0]}
ExtendedKeyUsage{extended_key_usage_critical}:
    * {extended_key_usage_0}
    * {extended_key_usage_1}
    * {extended_key_usage_2}
    * {extended_key_usage_3}
    * {extended_key_usage_4}
KeyUsage{key_usage_critical}:
    * {key_usage_0}
    * {key_usage_1}
    * {key_usage_2}
SubjectKeyIdentifier{subject_key_identifier_critical}:
    {subject_key_identifier_text}

X509 v3 certificate extensions for signed certificates:
* Certificate Revokation List (CRL): None
* Issuer URL: None
* OCSP URL: None
* Issuer Alternative Name: None

{pub[pem]}''',

}

# Root CAs with no children can always use the same template (since they all use the same extensions)
expected['dsa'] = expected['ecc']
expected['pwd'] = expected['ecc']


class ViewCATestCase(DjangoCAWithCATestCase):
    @override_tmpcadir()
    def test_all_cas(self):
        self.maxDiff = None
        for name, ca in sorted(self.cas.items(), key=lambda t: t[0]):
            stdout, stderr = self.cmd('view_ca', ca.serial)
            data = self.get_cert_context(name)
            self.assertMultiLineEqual(stdout, expected[name].format(**data))
            self.assertEqual(stderr, '')


@override_settings(USE_TZ=True)
class ViewCAWithTZTestCase(ViewCATestCase):
    pass
