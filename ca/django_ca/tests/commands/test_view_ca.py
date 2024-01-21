# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Test the view_ca management command."""
import os
import textwrap
from typing import Any
from unittest import mock

from cryptography import x509

from django.conf import settings
from django.test import TestCase

from django_ca.tests.base.mixins import TestCaseMixin
from django_ca.tests.base.utils import issuer_alternative_name, override_tmpcadir, uri
from django_ca.utils import format_general_name

expected = {
    "ec": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "ed25519": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "ed448": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "child": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): child.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): root.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Parent: {parent_name} ({parent_serial_colons})
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "root": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "root-no-extensions": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "root-no-wrap": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
{sha256}
{sha512}
""",
    "root-properties": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}
* Website: {ca.website}
* Terms of service: {ca.terms_of_service}
* CAA identity: {ca.caa_identity}

ACMEv2 support:
* Enabled: {ca.acme_enabled}
* Requires contact: {ca.acme_requires_contact}

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "root-acme-disabled": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "root-sign-options": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Authority Information Access:
  CA Issuers:
    * URI:{sign_authority_information_access[value][1][access_location][value]}
  OCSP:
    * URI:{sign_authority_information_access[value][0][access_location][value]}
* Certificate Policies:
  * Policy Identifier: 1.2.3
    Policy Qualifiers:
    * https://cps.example.com
    * User Notice:
      * Explicit Text: explicit-text
* CRL Distribution Points:
  * DistributionPoint:
    * Full Name:
      * URI:{sign_crl_distribution_points[value][0][full_name][0][value]}
* Issuer Alternative Name:
  * {sign_issuer_alternative_name}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "root-sign-options-only-issuer-alternative-name": """* Name: {name}
* Enabled: Yes
* Subject:
  * commonName (CN): {name}.example.com
* Serial: {serial_colons}
* Issuer:
  * commonName (CN): {name}.example.com
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Children:
  * {children[0][0]} ({children[0][1]})
* Maximum levels of sub-CAs (path length): {path_length_text}
* Path to private key:
  {key_path}

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

Certificate extensions for signed certificates:
* Issuer Alternative Name:
  * {sign_issuer_alternative_name}

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "globalsign": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): BE
  * organizationName (O): GlobalSign nv-sa
  * organizationalUnitName (OU): Root CA
  * commonName (CN): GlobalSign Root CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): BE
  * organizationName (O): GlobalSign nv-sa
  * organizationalUnitName (OU): Root CA
  * commonName (CN): GlobalSign Root CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "digicert_ev_root": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * organizationalUnitName (OU): www.digicert.com
  * commonName (CN): DigiCert High Assurance EV Root CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * organizationalUnitName (OU): www.digicert.com
  * commonName (CN): DigiCert High Assurance EV Root CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "comodo": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): GB
  * stateOrProvinceName (ST): Greater Manchester
  * localityName (L): Salford
  * organizationName (O): COMODO CA Limited
  * commonName (CN): COMODO RSA Certification Authority
* Serial: {serial_colons}
* Issuer:
  * countryName (C): GB
  * stateOrProvinceName (ST): Greater Manchester
  * localityName (L): Salford
  * organizationName (O): COMODO CA Limited
  * commonName (CN): COMODO RSA Certification Authority
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "identrust_root_1": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): IdenTrust
  * commonName (CN): IdenTrust Commercial Root CA 1
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): IdenTrust
  * commonName (CN): IdenTrust Commercial Root CA 1
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "globalsign_r2_root": """* Name: {name}
* Enabled: Yes
* Subject:
  * organizationalUnitName (OU): GlobalSign Root CA - R2
  * organizationName (O): GlobalSign
  * commonName (CN): GlobalSign
* Serial: {serial_colons}
* Issuer:
  * organizationalUnitName (OU): GlobalSign Root CA - R2
  * organizationName (O): GlobalSign
  * commonName (CN): GlobalSign
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "comodo_dv": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): GB
  * stateOrProvinceName (ST): Greater Manchester
  * localityName (L): Salford
  * organizationName (O): COMODO CA Limited
  * commonName (CN): COMODO RSA Domain Validation Secure Server CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): GB
  * stateOrProvinceName (ST): Greater Manchester
  * localityName (L): Salford
  * organizationName (O): COMODO CA Limited
  * commonName (CN): COMODO RSA Certification Authority
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): 0
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "rapidssl_g3": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): GeoTrust Inc.
  * commonName (CN): RapidSSL SHA256 CA - G3
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): GeoTrust Inc.
  * commonName (CN): GeoTrust Global CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "geotrust": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): GeoTrust Inc.
  * commonName (CN): GeoTrust Global CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): GeoTrust Inc.
  * commonName (CN): GeoTrust Global CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "comodo_ev": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): GB
  * stateOrProvinceName (ST): Greater Manchester
  * localityName (L): Salford
  * organizationName (O): COMODO CA Limited
  * commonName (CN): COMODO RSA Extended Validation Secure Server CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): GB
  * stateOrProvinceName (ST): Greater Manchester
  * localityName (L): Salford
  * organizationName (O): COMODO CA Limited
  * commonName (CN): COMODO RSA Certification Authority
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): 0
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "digicert_ha_intermediate": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * organizationalUnitName (OU): www.digicert.com
  * commonName (CN): DigiCert SHA2 High Assurance Server CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * organizationalUnitName (OU): www.digicert.com
  * commonName (CN): DigiCert High Assurance EV Root CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): 0
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "dst_root_x3": """* Name: {name}
* Enabled: Yes
* Subject:
  * organizationName (O): Digital Signature Trust Co.
  * commonName (CN): DST Root CA X3
* Serial: {serial_colons}
* Issuer:
  * organizationName (O): Digital Signature Trust Co.
  * commonName (CN): DST Root CA X3
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "globalsign_dv": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): BE
  * organizationName (O): GlobalSign nv-sa
  * commonName (CN): GlobalSign Domain Validation CA - SHA256 - G2
* Serial: {serial_colons}
* Issuer:
  * countryName (C): BE
  * organizationName (O): GlobalSign nv-sa
  * organizationalUnitName (OU): Root CA
  * commonName (CN): GlobalSign Root CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "godaddy_g2_intermediate": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * stateOrProvinceName (ST): Arizona
  * localityName (L): Scottsdale
  * organizationName (O): GoDaddy.com, Inc.
  * organizationalUnitName (OU): http://certs.godaddy.com/repository/
  * commonName (CN): Go Daddy Secure Certificate Authority - G2
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * stateOrProvinceName (ST): Arizona
  * localityName (L): Scottsdale
  * organizationName (O): GoDaddy.com, Inc.
  * commonName (CN): Go Daddy Root Certificate Authority - G2
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "godaddy_g2_root": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * stateOrProvinceName (ST): Arizona
  * localityName (L): Scottsdale
  * organizationName (O): GoDaddy.com, Inc.
  * commonName (CN): Go Daddy Root Certificate Authority - G2
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * stateOrProvinceName (ST): Arizona
  * localityName (L): Scottsdale
  * organizationName (O): GoDaddy.com, Inc.
  * commonName (CN): Go Daddy Root Certificate Authority - G2
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "google_g3": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): Google Trust Services
  * commonName (CN): Google Internet Authority G3
* Serial: {serial_colons}
* Issuer:
  * organizationalUnitName (OU): GlobalSign Root CA - R2
  * organizationName (O): GlobalSign
  * commonName (CN): GlobalSign
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "letsencrypt_x1": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): Let's Encrypt
  * commonName (CN): Let's Encrypt Authority X1
* Serial: {serial_colons}
* Issuer:
  * organizationName (O): Digital Signature Trust Co.
  * commonName (CN): DST Root CA X3
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Name Constraints{name_constraints_critical}:
{name_constraints_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "letsencrypt_x3": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): Let's Encrypt
  * commonName (CN): Let's Encrypt Authority X3
* Serial: {serial_colons}
* Issuer:
  * organizationName (O): Digital Signature Trust Co.
  * commonName (CN): DST Root CA X3
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "startssl_root": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): IL
  * organizationName (O): StartCom Ltd.
  * organizationalUnitName (OU): Secure Digital Certificate Signing
  * commonName (CN): StartCom Certification Authority
* Serial: {serial_colons}
* Issuer:
  * countryName (C): IL
  * organizationName (O): StartCom Ltd.
  * organizationalUnitName (OU): Secure Digital Certificate Signing
  * commonName (CN): StartCom Certification Authority
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}
* Unknown extension (2.16.840.1.113730.1.1):
  03:02:00:07
* Unknown extension (2.16.840.1.113730.1.13):
  16:29:53:74:61:72:74:43:6F:6D:20:46:72:65:65:20:53:53:4C:20:43:65:72:74:69:66:69:63:61:74:69:6F:6E:20:41:75:74:68:6F:72:69:74:79

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "startssl_class2": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): IL
  * organizationName (O): StartCom Ltd.
  * organizationalUnitName (OU): Secure Digital Certificate Signing
  * commonName (CN): StartCom Class 2 Primary Intermediate Server CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): IL
  * organizationName (O): StartCom Ltd.
  * organizationalUnitName (OU): Secure Digital Certificate Signing
  * commonName (CN): StartCom Certification Authority
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "startssl_class3": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): IL
  * organizationName (O): StartCom Ltd.
  * organizationalUnitName (OU): StartCom Certification Authority
  * commonName (CN): StartCom Class 3 OV Server CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): IL
  * organizationName (O): StartCom Ltd.
  * organizationalUnitName (OU): Secure Digital Certificate Signing
  * commonName (CN): StartCom Certification Authority
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): {path_length_text}
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "trustid_server_a52": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): IdenTrust
  * organizationalUnitName (OU): TrustID Server
  * commonName (CN): TrustID Server CA A52
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): IdenTrust
  * commonName (CN): IdenTrust Commercial Root CA 1
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Extended Key Usage{extended_key_usage_critical}:
{extended_key_usage_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "digicert_global_root": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * organizationalUnitName (OU): www.digicert.com
  * commonName (CN): DigiCert Global Root CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * organizationalUnitName (OU): www.digicert.com
  * commonName (CN): DigiCert Global Root CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Valid

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): unlimited
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
    "digicert_sha2": """* Name: {name}
* Enabled: Yes
* Subject:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * commonName (CN): DigiCert SHA2 Secure Server CA
* Serial: {serial_colons}
* Issuer:
  * countryName (C): US
  * organizationName (O): DigiCert Inc
  * organizationalUnitName (OU): www.digicert.com
  * commonName (CN): DigiCert Global Root CA
* Valid from: {valid_from_str}
* Valid until: {valid_until_str}
* Status: Expired

Certificate Authority information:
* Certificate authority is a root CA.
* Certificate authority has no children.
* Maximum levels of sub-CAs (path length): 0
* Private key not available locally.

ACMEv2 support:
* Enabled: False

Certificate extensions:
* Authority Information Access{authority_information_access_critical}:
{authority_information_access_text}
* Authority Key Identifier{authority_key_identifier_critical}:
{authority_key_identifier_text}
* Basic Constraints{basic_constraints_critical}:
{basic_constraints_text}
* CRL Distribution Points{crl_distribution_points_critical}:
{crl_distribution_points_text}
* Certificate Policies{certificate_policies_critical}:
{certificate_policies_text}
* Key Usage{key_usage_critical}:
{key_usage_text}
* Subject Key Identifier{subject_key_identifier_critical}:
{subject_key_identifier_text}

No certificate extensions for signed certificates.

Digest:
  SHA-256: {sha256}
  SHA-512: {sha512}

{pub[pem]}""",
}

# Root CAs with no children can always use the same template (since they all use the same extensions)
expected["dsa"] = expected["ec"]
expected["pwd"] = expected["ec"]


class ViewCATestCase(TestCaseMixin, TestCase):
    """Main test class for this command."""

    load_cas = "__all__"

    def _wrap_hash(self, text: str, columns: int) -> str:
        return "\n".join(textwrap.wrap(text, columns, subsequent_indent=" " * 11))

    @override_tmpcadir()
    def test_all_cas(self) -> None:
        """Test viewing all CAs."""
        for name, ca in sorted(self.cas.items(), key=lambda t: t[0]):
            stdout, stderr = self.cmd("view_ca", ca.serial, wrap=False)
            data = self.get_cert_context(name)
            self.assertMultiLineEqual(stdout, expected[name].format(**data), name)
            self.assertEqual(stderr, "")

    @override_tmpcadir(USE_TZ=True)
    def test_with_timezone_support(self) -> None:
        """Test viewing certificate with USE_TZ=True."""
        self.assertTrue(settings.USE_TZ)

        stdout, stderr = self.cmd("view_ca", self.ca.serial, wrap=False)
        data = self.get_cert_context(self.ca.name)
        self.assertMultiLineEqual(stdout, expected[self.ca.name].format(**data), self.ca.name)
        self.assertEqual(stderr, "")

    @override_tmpcadir(USE_TZ=False)
    def test_with_use_tz_is_false(self) -> None:
        """Test viewing certificate without timezone support."""
        self.assertFalse(settings.USE_TZ)

        stdout, stderr = self.cmd("view_ca", self.ca.serial, wrap=False)
        data = self.get_cert_context(self.ca.name)
        self.assertMultiLineEqual(stdout, expected[self.ca.name].format(**data), self.ca.name)
        self.assertEqual(stderr, "")

    @override_tmpcadir()
    def test_properties(self) -> None:
        """Test viewing of various optional properties."""
        ca = self.cas["root"]
        hostname = "ca.example.com"
        ca.website = f"https://website.{hostname}"
        ca.terms_of_service = f"{ca.website}/tos/"
        ca.caa_identity = hostname
        ca.acme_enabled = True
        ca.acme_requires_contact = False
        ca.save()

        stdout, stderr = self.cmd("view_ca", ca.serial, wrap=False)
        self.assertEqual(stderr, "")
        data = self.get_cert_context("root")
        self.assertMultiLineEqual(stdout, expected["root-properties"].format(ca=ca, **data))

    @override_tmpcadir(CA_ENABLE_ACME=False)
    def test_acme_disabled(self) -> None:
        """Test viewing when ACME is disabled."""
        stdout, stderr = self.cmd("view_ca", self.cas["root"].serial, wrap=False)
        self.assertEqual(stderr, "")
        data = self.get_cert_context("root")
        self.assertMultiLineEqual(stdout, expected["root-acme-disabled"].format(**data))

    @override_tmpcadir()
    def test_no_extensions(self) -> None:
        """Test viewing a CA without extensions."""
        stdout, stderr = self.cmd("view_ca", self.cas["root"].serial, extensions=False, wrap=False)
        self.assertEqual(stderr, "")
        data = self.get_cert_context("root")
        self.assertMultiLineEqual(stdout, expected["root-no-extensions"].format(**data))

    @override_tmpcadir()
    def test_no_no_private_key(self) -> None:
        """Test viewing when we have no private key."""

        def side_effect(cls: Any) -> None:
            raise NotImplementedError

        ca_storage = "django_ca.management.commands.view_ca.ca_storage.%s"
        with self.patch(ca_storage % "path", side_effect=side_effect) as path_mock, self.patch(
            ca_storage % "exists", return_value=True
        ) as exists_mock:
            stdout, stderr = self.cmd("view_ca", self.cas["root"].serial, wrap=False)

        path_mock.assert_called_once_with(self.cas["root"].private_key_path)
        exists_mock.assert_called_once_with(self.cas["root"].private_key_path)
        data = self.get_cert_context("root")
        data["key_path"] = self.cas["root"].private_key_path
        self.assertMultiLineEqual(stdout, expected["root"].format(**data))
        self.assertEqual(stderr, "")

    @override_tmpcadir()
    def test_sign_options(self) -> None:
        """Test options for signing certificates."""
        ian_uri = uri("http://ian.example.com")
        ca = self.cas["root"]
        self.assertIsNotNone(ca.sign_authority_information_access)
        ca.sign_certificate_policies = self.certificate_policies(
            x509.PolicyInformation(
                policy_identifier=x509.ObjectIdentifier("1.2.3"),
                policy_qualifiers=[
                    "https://cps.example.com",
                    x509.UserNotice(notice_reference=None, explicit_text="explicit-text"),
                ],
            )
        )
        self.assertIsNotNone(ca.sign_crl_distribution_points)
        ca.sign_issuer_alternative_name = issuer_alternative_name(ian_uri)
        ca.save()

        stdout, stderr = self.cmd("view_ca", ca.serial, wrap=False)
        self.assertEqual(stderr, "")
        data = self.get_cert_context("root")
        data["sign_issuer_alternative_name"] = format_general_name(ian_uri)
        self.assertMultiLineEqual(stdout, expected["root-sign-options"].format(**data))

    @override_tmpcadir()
    def test_sign_options_only_issuer_alternative_name(self) -> None:
        """Test options for signing certificates with only an Issuer Alternative Name.

        This is necessary to check full branch coverage, otherwise Authority Information Access and CRL
        Distribution Points is always set.
        """
        ian_uri = uri("http://ian.example.com")
        ca = self.cas["root"]
        ca.sign_authority_information_access = None
        ca.sign_certificate_policies = None
        ca.sign_crl_distribution_points = None
        ca.sign_issuer_alternative_name = issuer_alternative_name(ian_uri)
        ca.save()

        stdout, stderr = self.cmd("view_ca", ca.serial, wrap=False)
        self.assertEqual(stderr, "")
        data = self.get_cert_context("root")
        data["sign_issuer_alternative_name"] = format_general_name(ian_uri)
        self.assertMultiLineEqual(
            stdout, expected["root-sign-options-only-issuer-alternative-name"].format(**data)
        )

    def test_wrap_digest(self) -> None:
        """Test wrapping the digest."""
        data = self.get_cert_context("root")
        sha256 = data["sha256"]
        sha512 = data["sha512"]

        with mock.patch("shutil.get_terminal_size", return_value=os.terminal_size((64, 0))) as shutil_mock:
            stdout, stderr = self.cmd("view_ca", self.cas["root"].serial, pem=False, extensions=False)

        # Django calls get_terminal_size as well, so the number of calls is unpredictable
        shutil_mock.assert_called_with(fallback=(107, 100))
        self.assertEqual(stderr, "")

        data["sha256"] = self._wrap_hash(f"  SHA-256: {sha256}", 62)
        data["sha512"] = self._wrap_hash(f"  SHA-512: {sha512}", 62)
        self.assertMultiLineEqual(stdout, expected["root-no-wrap"].format(**data))

        # try with decreasing terminal size
        with mock.patch("shutil.get_terminal_size", return_value=os.terminal_size((63, 0))) as shutil_mock:
            stdout, stderr = self.cmd("view_ca", self.cas["root"].serial, pem=False, extensions=False)
        self.assertMultiLineEqual(stdout, expected["root-no-wrap"].format(**data))

        with mock.patch("shutil.get_terminal_size", return_value=os.terminal_size((62, 0))) as shutil_mock:
            stdout, stderr = self.cmd("view_ca", self.cas["root"].serial, pem=False, extensions=False)
        self.assertMultiLineEqual(stdout, expected["root-no-wrap"].format(**data))

        # Get smaller, so we wrap another element in the colon'd hash
        with mock.patch("shutil.get_terminal_size", return_value=os.terminal_size((61, 0))) as shutil_mock:
            stdout, stderr = self.cmd("view_ca", self.cas["root"].serial, pem=False, extensions=False)
        data["sha256"] = self._wrap_hash(f"  SHA-256: {sha256}", 59)
        data["sha512"] = self._wrap_hash(f"  SHA-512: {sha512}", 59)
        self.assertMultiLineEqual(stdout, expected["root-no-wrap"].format(**data))
