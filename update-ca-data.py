#!/usr/bin/env python3
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

"""Update tables for ca_examples.rst in docs."""
# pylint: disable=invalid-name; pylint complains about dashes in script name
# pylint: enable=invalid-name; this enables the check for the rest of the script

import argparse
import os

from tabulate import tabulate

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import common

common.setup_django()

# pylint: disable=import-error,wrong-import-position,wrong-import-order
from django_ca.extensions import KeyUsage  # NOQA: E402
from django_ca.utils import bytes_to_hex  # NOQA: E402
from django_ca.utils import format_general_name  # NOQA: E402
from django_ca.utils import format_name  # NOQA: E402

# pylint: enable=import-error,wrong-import-position,wrong-import-order

HASH_NAMES = {
    hashes.SHA1: "SHA-1",
    hashes.SHA256: "SHA-256",
}

parser = argparse.ArgumentParser(description="Update tables for ca_examples.rst in docs.")
args = parser.parse_args()

docs_base = os.path.join(common.ROOTDIR, "docs", "source")
out_base = os.path.join(docs_base, "generated")
if not os.path.exists(out_base):
    os.makedirs(out_base)


def optional(value, formatter=None, fallback=None):
    """Small function to get an value if set or a fallback."""

    if not value:
        return fallback
    if callable(formatter):
        return formatter(value)
    if formatter is not None:
        return formatter
    return value


cert_dir = os.path.join(docs_base, "_files", "cert")
ca_dir = os.path.join(docs_base, "_files", "ca")
certs = {
    "digicert_sha2.pem": {  # derstandard.at
        "name": "DigiCert Secure Server",
        "last": "2019-07-06",
    },
    "letsencrypt_x3.pem": {  # jabber.at
        "name": "Let's Encrypt X3",
        "last": "2019-07-06",
    },
    "godaddy_g2_intermediate.pem": {
        "name": "Go Daddy G2 Intermediate",
        "last": "2019-04-19",
    },
    "google_g3.pem": {
        "name": "Google G3",
        "last": "2019-04-19",
    },
    "letsencrypt_x1.pem": {
        "name": "Let's Encrypt X1",
        "last": "2016-04-22",
    },
    "rapidssl_g3.pem": {
        "name": "RapidSSL G3",
        "last": "2016-04-23",
    },
    "comodo_ev.pem": {
        "name": "Comodo EV",
        "last": "2019-04-21",
    },
    "comodo_dv.pem": {
        "name": "Comodo DV",
        "last": "2016-04-23",
    },
    "startssl_class2.pem": {
        "name": "StartSSL class 2",
        "last": "2016-04-22",
    },
    "startssl_class3.pem": {
        "name": "StartSSL class 3",
        "last": "2016-04-22",
    },
    "globalsign_dv.pem": {
        "name": "GlobalSign DV",
        "last": "2016-04-23",
    },
    "digicert_ha_intermediate.pem": {
        "name": "DigiCert HA Intermediate",
        "last": "2019-04-21",
    },
    "trustid_server_a52.pem": {
        "name": "TrustID Server A52",
        "last": "2019-04-21",
    },
}
cas = {
    "digicert_sha2.pem": {  # derstandard.at
        "name": "DigiCert Secure Server",
        "last": "2019-07-06",
        "info": "Signed by DigiCert Global Root",
    },
    "digicert_global_root.pem": {  # derstandard.at
        "name": "DigiCert Global Root",
        "last": "2019-07-06",
    },
    "dst_root_x3.pem": {
        "name": "DST X3",
        "last": "2019-04-19",
        "info": "Root CA",
    },
    "godaddy_g2_root.pem": {
        "name": "Go Daddy G2",
        "last": "2019-04-19",
        "info": "Root CA",
    },
    "godaddy_g2_intermediate.pem": {
        "name": "Go Daddy G2 Intermediate",
        "last": "2019-04-19",
        "info": "Signed by Go Daddy G2",
    },
    "letsencrypt_x1.pem": {
        "name": "Let's Encrypt X1",
        "last": "2016-04-22",
        "info": "Signed by ???",
    },
    "letsencrypt_x3.pem": {
        "name": "Let's Encrypt X3",
        "last": "2019-04-19",
        "info": "Signed by DST X3",
    },
    "google_g3.pem": {
        "name": "Google G3",
        "last": "2019-04-19",
        "info": "Signed by GlobalSign R2",
    },
    "globalsign_r2_root.pem": {
        "name": "GlobalSign R2",
        "last": "2019-04-19",
        "info": "Root CA",
    },
    "startssl_root.pem": {
        "name": "StartSSL",
        "last": "2016-04-22",
        "info": "Root CA",
    },
    "startssl_class2.pem": {
        "name": "StartSSL class 2",
        "last": "2016-04-22",
        "info": "Signed by StartSSL",
    },
    "startssl_class3.pem": {
        "name": "StartSSL class 2",
        "last": "2016-04-22",
        "info": "Signed by StartSSL",
    },
    "geotrust.pem": {
        "name": "GeoTrust",
        "last": "2016-04-23",
        "info": "Root CA",
    },
    "rapidssl_g3.pem": {
        "name": "RapidSSL G3",
        "last": "2016-04-23",
        "info": "Signed by GeoTrust",
    },
    "comodo.pem": {
        "name": "Comodo",
        "last": "2019-04-21",
        "info": "Root CA",
    },
    "comodo_ev.pem": {
        "name": "Comodo EV",
        "last": "2019-04-21",
        "info": "Signed by Comodo",
    },
    "comodo_dv.pem": {
        "name": "Comodo DV",
        "last": "2016-04-23",
        "info": "Signed by Comodo",
    },
    "globalsign.pem": {
        "name": "GlobalSign",
        "last": "2016-04-23",
        "info": "Root CA",
    },
    "globalsign_dv.pem": {
        "name": "GlobalSign DV",
        "last": "2016-04-23",
        "info": "Signed by GlobalSign",
    },
    "digicert_ev_root.pem": {
        "name": "DigiCert EV Root",
        "last": "2019-04-21",
        "info": "Root CA",
    },
    "digicert_ha_intermediate.pem": {
        "name": "DigiCert HA Intermediate",
        "last": "2019-04-21",
        "info": "Signed by DigiCert EV Root",
    },
    "identrust_root_1.pem": {
        "name": "IdenTrust",
        "last": "2019-04-21",
        "info": "Root CA",
    },
    "trustid_server_a52.pem": {
        "name": "TrustID Server A52",
        "last": "2019-04-21",
        "info": "Signed by IdenTrust",
    },
}


def ref_as_str(ref):
    """Convert a CertificatePolicies reference to a str."""

    numbers = [str(n) for n in ref.notice_numbers]
    return "%s: %s" % (ref.organization, ", ".join(numbers))


def policy_as_str(policy):
    """Convert a CertificatePolicies policy to a str."""

    if isinstance(policy, str):
        return policy
    if policy.explicit_text is None and policy.notice_reference is None:
        return "Empty UserNotice"
    if policy.notice_reference is None:
        return "User Notice: %s" % policy.explicit_text
    if policy.explicit_text is None:
        return "User Notice: %s" % (ref_as_str(policy.notice_reference))

    return "User Notice: %s: %s" % (ref_as_str(policy.notice_reference), policy.explicit_text)


def update_cert_data(prefix, dirname, cert_data, name_header):
    """Update certificate/ca data."""

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements; there are many extensions

    cert_values = {
        "subject": [
            (
                name_header,
                "Subject",
            )
        ],
        "issuer": [
            (
                name_header,
                "Issuer",
            )
        ],
        "aia": [(name_header, "Critical", "Values")],
        "aki": [(name_header, "Critical", "Key identifier", "Issuer", "Serial")],
        "basicconstraints": [(name_header, "Critical", "CA", "Path length")],
        "eku": [(name_header, "Critical", "Usages")],
        "key_usage": [[name_header, "Critical"] + sorted(KeyUsage.CRYPTOGRAPHY_MAPPING.keys())],
        "ian": [(name_header, "Critical", "Names")],
        "ski": [(name_header, "Critical", "Digest")],
        "certificatepolicies": [(name_header, "Critical", "Policies")],
        "crldp": [(name_header, "Critical", "Names", "RDNs", "Issuer", "Reasons")],
        "sct": [(name_header, "Critical", "Value")],
        "nc": [(name_header, "Critical", "Permitted", "Excluded")],
        "unknown": [(name_header, "Extensions")],
    }
    exclude_empty_lines = {
        "unknown",
    }

    for cert_filename in sorted(os.listdir(dirname), key=lambda f: cert_data.get(f, {}).get("name", "")):
        if cert_filename not in cert_data:
            common.warn("Unknown %s: %s" % (prefix, cert_filename))
            continue
        print("Parsing %s (%s)..." % (cert_filename, prefix))

        cert_name = cert_data[cert_filename]["name"]

        this_cert_values = {}
        for cert_key in cert_values:
            this_cert_values[cert_key] = [""]

        with open(os.path.join(dirname, cert_filename), "rb") as cert_stream:
            cert = x509.load_pem_x509_certificate(cert_stream.read(), backend=default_backend())

        this_cert_values["subject"] = ["``%s``" % format_name(cert.subject)]
        this_cert_values["issuer"] = ["``%s``" % format_name(cert.issuer)]

        for cert_ext in cert.extensions:
            value = cert_ext.value
            critical = "✓" if cert_ext.critical else "✗"

            if isinstance(value, x509.AuthorityInformationAccess):
                this_cert_values["aia"] = [
                    critical,
                    "\n".join(
                        [
                            "* %s: %s"
                            % (
                                v.access_method._name,  # pylint: disable=protected-access
                                format_general_name(v.access_location),
                            )
                            for v in value
                        ]
                    ),
                ]
            elif isinstance(value, x509.AuthorityKeyIdentifier):
                this_cert_values["aki"] = [
                    critical,
                    bytes_to_hex(value.key_identifier),
                    optional(value.authority_cert_issuer, format_general_name, "✗"),
                    optional(value.authority_cert_serial_number, fallback="✗"),
                ]
            elif isinstance(value, x509.BasicConstraints):
                this_cert_values["basicconstraints"] = [
                    critical,
                    value.ca,
                    value.path_length if value.path_length is not None else "None",
                ]
            elif isinstance(value, x509.CRLDistributionPoints):
                this_cert_values["crldp"] = []
                for distribution_point in value:
                    full_name = (
                        "* ".join([format_general_name(name) for name in distribution_point.full_name])
                        if distribution_point.full_name
                        else "✗"
                    )
                    issuer = (
                        "* ".join([format_general_name(name) for name in distribution_point.crl_issuer])
                        if distribution_point.crl_issuer
                        else "✗"
                    )
                    reasons = (
                        ", ".join([r.name for r in distribution_point.reasons])
                        if distribution_point.reasons
                        else "✗"
                    )

                    relative_name = (
                        format_name(distribution_point.relative_name)
                        if distribution_point.relative_name
                        else "✗"
                    )
                    this_cert_values["crldp"].append(
                        [
                            critical,
                            full_name,
                            relative_name,
                            issuer,
                            reasons,
                        ]
                    )
            elif isinstance(value, x509.CertificatePolicies):
                policies = []

                for policy in value:
                    policy_name = policy.policy_identifier.dotted_string
                    if policy.policy_qualifiers is None:
                        policies.append("* %s" % policy_name)
                    elif len(policy.policy_qualifiers) == 1:
                        policies.append(
                            "* %s: %s" % (policy_name, policy_as_str(policy.policy_qualifiers[0]))
                        )
                    else:
                        qualifiers = "\n".join(
                            ["  * %s" % policy_as_str(p) for p in policy.policy_qualifiers]
                        )
                        policies.append("* %s:\n\n%s\n" % (policy_name, qualifiers))

                this_cert_values["certificatepolicies"] = [critical, "\n".join(policies)]
            elif isinstance(value, x509.ExtendedKeyUsage):
                this_cert_values["eku"] = [
                    critical,
                    ", ".join([u._name for u in value]),  # pylint: disable=protected-access
                ]
            elif isinstance(value, x509.IssuerAlternativeName):
                this_cert_values["ian"] = [
                    critical,
                    "* ".join([format_general_name(v) for v in value]),
                ]
            elif isinstance(value, x509.KeyUsage):
                key_usages = []
                for key in cert_values["key_usage"][0][2:]:
                    try:
                        key_usages.append("✓" if getattr(value, KeyUsage.CRYPTOGRAPHY_MAPPING[key]) else "✗")
                    except ValueError:
                        key_usages.append("✗")

                this_cert_values["key_usage"] = [
                    critical,
                ] + key_usages
            elif isinstance(value, x509.NameConstraints):
                permitted = (
                    "\n".join(["* %s" % format_general_name(n) for n in value.permitted_subtrees])
                    if value.permitted_subtrees
                    else "✗"
                )
                excluded = (
                    "\n".join(["* %s" % format_general_name(n) for n in value.excluded_subtrees])
                    if value.excluded_subtrees
                    else "✗"
                )
                this_cert_values["nc"] = [critical, permitted, excluded]
            elif isinstance(value, x509.PrecertificateSignedCertificateTimestamps):
                this_cert_values["sct"] = [
                    critical,
                    "\n".join(
                        ["* Type: %s, version: %s" % (e.entry_type.name, e.version.name) for e in value]
                    ),
                ]
            elif isinstance(value, x509.SubjectKeyIdentifier):
                this_cert_values["ski"] = [critical, bytes_to_hex(value.digest)]
            elif isinstance(value, x509.SubjectAlternativeName):
                continue  # not interesting here
            else:
                # These are some OIDs identified by OpenSSL cli as "Netscape Cert Type" and
                # "Netscape Comment". They only occur in the old, discontinued StartSSL root
                # certificate.
                if cert_ext.oid.dotted_string == "2.16.840.1.113730.1.1":
                    name = "Netscape Cert Type"
                elif cert_ext.oid.dotted_string == "2.16.840.1.113730.1.13":
                    name = "Netscape Comment"
                else:
                    name = cert_ext.oid._name  # pylint: disable=protected-access; only way to get name

                ext_str = "%s (Critical: %s, OID: %s)" % (name, cert_ext.critical, cert_ext.oid.dotted_string)
                this_cert_values["unknown"].append(ext_str)

        this_cert_values["unknown"] = ["\n".join(["* %s" % v for v in this_cert_values["unknown"][1:]])]

        for key, row in this_cert_values.items():
            if isinstance(row[0], list):
                cert_values[key].append([cert_name] + row[0])
                for mrow in row[1:]:
                    cert_values[key].append(["", ""] + mrow[1:])
            else:
                cert_values[key].append([cert_name] + row)

    for name, values in cert_values.items():
        cert_filename = os.path.join(out_base, "%s_%s.rst" % (prefix, name))

        if name in exclude_empty_lines:
            values = [v for v in values if "".join(v[1:])]

        if values:
            table = tabulate(values, headers="firstrow", tablefmt="rst")
        else:
            table = ""

        with open(cert_filename, "w") as stream:
            stream.write(table)


def update_crl_data():  # pylint: disable=too-many-locals
    """Update CRL data."""
    crls = {
        "gdig2s1-1015.crl": {
            "info": "CRL in Go Daddy G2 end user certificates",
            "last": "2019-04-19",
            "name": "Go Daddy G2/user",
            "url": "http://crl.godaddy.com/gdig2s1-1015.crl",
        },
        "gdroot-g2.crl": {
            "info": "CRL in Go Daddy G2 intermediate CA",
            "last": "2019-04-19",
            "name": "Go Daddy G2/ca",
            "url": "http://crl.godaddy.com/gdroot-g2.crl",
        },
        "DSTROOTCAX3CRL.crl": {
            "info": "CRL in Let's Encrypt X3",
            "last": "2019-04-19",
            "name": "Let's Encrypt Authority X3/ca",
            "url": "http://crl.identrust.com/DSTROOTCAX3CRL.crl",
        },
        "root-r2.crl": {
            "info": "CRL in GlobalSign R2",
            "last": "2019-04-19",
            "name": "GlobalSign R2/ca",
            "url": "http://crl.globalsign.net/root-r2.crl",
        },
        "gsr2.crl": {
            "info": "CRL in Google G3 CA",
            "last": "2019-04-19",
            "name": "Google G3/ca",
            "url": "http://crl.pki.goog/gsr2/gsr2.crl",
        },
        "GTSGIAG3.crl": {
            "info": "CRL in Google G3 end user certificates",
            "last": "2019-04-19",
            "name": "Google G3/user",
            "url": "http://crl.pki.goog/GTSGIAG3.crl",
        },
        "comodo_ev_user.pem": {
            "info": "CRL in %s end user certificates" % certs["comodo_ev.pem"]["name"],
            "last": "2019-04-21",
            "name": "%s (user)" % cas["comodo_ev.pem"]["name"],
            "url": "http://crl.comodoca.com/COMODORSAExtendedValidationSecureServerCA.crl",
        },
        "digicert_ha_intermediate.crl": {
            "info": "CRL in %s" % cas["digicert_ha_intermediate.pem"]["name"],
            "last": "2019-04-21",
            "name": "%s/ca" % cas["digicert_ha_intermediate.pem"]["name"],
            "url": "http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl",
        },
        "digicert_ha_intermediate_user.crl": {
            "info": "CRL %s end user certificates" % cas["digicert_ha_intermediate.pem"]["name"],
            "last": "2019-04-21",
            "name": "%s/user" % certs["digicert_ha_intermediate.pem"]["name"],
            "url": "http://crl3.digicert.com/sha2-ha-server-g6.crl",
        },
        "trustid_server_a52_ca.crl": {
            "info": "CRL in %s" % cas["trustid_server_a52.pem"]["name"],
            "last": "2019-04-21",
            "name": "%s/ca" % cas["trustid_server_a52.pem"]["name"],
            "url": "http://validation.identrust.com/crl/commercialrootca1.crl",
        },
        "trustid_server_a52_user.crl": {
            "info": "CRL %s end user certificates" % cas["trustid_server_a52.pem"]["name"],
            "last": "2019-04-21",
            "name": "%s/user" % certs["trustid_server_a52.pem"]["name"],
            "url": "http://validation.identrust.com/crl/trustidcaa52.crl",
        },
    }

    crl_dir = os.path.join(docs_base, "_files", "crl")
    crl_values = {
        # meta data
        "crl_info": [("CRL", "Source", "Last accessed", "Info")],
        "crl_issuer": [("CRL", "Issuer Name")],
        "crl_data": [("CRL", "Update freq.", "hash")],
        # extensions
        "crl_aki": [("CRL", "key_identifier", "cert_issuer", "cert_serial")],
        "crl_crlnumber": [("CRL", "number")],
        "crl_idp": [
            (
                "CRL",
                "full name",
                "relative name",
                "only attribute certs",
                "only ca certs",
                "only user certs",
                "reasons",
                "indirect CRL",
            ),
        ],
    }

    for crl_filename in sorted(os.listdir(crl_dir), key=lambda f: crls.get(f, {}).get("name", "")):
        if crl_filename not in crls:
            common.warn("Unknown CRL: %s" % crl_filename)
            continue

        crl_name = crls[crl_filename]["name"]

        # set empty string as default value
        this_crl_values = {}
        for crl_key in crl_values:
            this_crl_values[crl_key] = [""] * (len(crl_values[crl_key][0]) - 1)

        with open(os.path.join(crl_dir, crl_filename), "rb") as crl_stream:
            crl = x509.load_der_x509_crl(crl_stream.read(), backend=default_backend())

        # add info
        this_crl_values["crl_info"] = (
            ":download:`%s </_files/crl/%s>` (`URL <%s>`__)"
            % (crl_filename, crl_filename, crls[crl_filename]["url"]),
            crls[crl_filename]["last"],
            crls[crl_filename]["info"],
        )

        # add data row
        this_crl_values["crl_data"] = (
            crl.next_update - crl.last_update,
            HASH_NAMES[type(crl.signature_hash_algorithm)],
        )
        this_crl_values["crl_issuer"] = ("``%s``" % format_name(crl.issuer),)

        # add extension values
        for ext in crl.extensions:
            value = ext.value

            if isinstance(value, x509.CRLNumber):
                this_crl_values["crl_crlnumber"] = (ext.value.crl_number,)
            elif isinstance(value, x509.IssuingDistributionPoint):
                this_crl_values["crl_idp"] = (
                    optional(value.full_name, lambda v: "* ".join([format_general_name(n) for n in v]), "✗"),
                    optional(value.relative_name, format_name, "✗"),
                    "✓" if value.only_contains_attribute_certs else "✗",
                    "✓" if value.only_contains_ca_certs else "✗",
                    "✓" if value.only_contains_user_certs else "✗",
                    optional(value.only_some_reasons, lambda v: ", ".join([f.name for f in v]), "✗"),
                    "✓" if value.indirect_crl else "✗",
                )
            elif isinstance(value, x509.AuthorityKeyIdentifier):
                crl_aci = optional(
                    value.authority_cert_issuer,
                    lambda v: "* ".join(["``%s``" % format_general_name(n) for n in v]),
                    "✗",
                )
                crl_acsn = optional(value.authority_cert_serial_number, fallback="✗")

                this_crl_values["crl_aki"] = (bytes_to_hex(value.key_identifier), crl_aci, crl_acsn)
            else:
                common.warn("Unknown extension: %s" % ext.oid._name)  # pylint: disable=protected-access

        for crl_key, crl_row in this_crl_values.items():
            crl_values[crl_key].append([crl_name] + list(crl_row))

    # Finally, write CRL data to RST table
    for crl_name, crl_extensions in crl_values.items():
        crl_table = tabulate(crl_extensions, headers="firstrow", tablefmt="rst")
        with open(os.path.join(out_base, "%s.rst" % crl_name), "w") as crl_table_stream:
            crl_table_stream.write(crl_table)


######################
# Generate Cert data #
######################

update_cert_data("cert", cert_dir, certs, "Certificate")
update_cert_data("ca", ca_dir, cas, "CA")
update_crl_data()
