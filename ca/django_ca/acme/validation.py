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

"""Module collecting methods for ACME challenge validation."""

import ipaddress
import logging
from http import HTTPStatus

import dns.exception
import requests
from dns import resolver

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from django_ca.acme.errors import AcmeBadCSR
from django_ca.models import AcmeAuthorization, AcmeChallenge
from django_ca.utils import check_name

log = logging.getLogger(__name__)


def validate_http_01(challenge: AcmeChallenge) -> bool:
    """Function to validate an HTTP-01 challenge.

    .. seealso:: `RFC 8555, section 8.3 <https://datatracker.ietf.org/doc/html/rfc8555#section-8.3>`_
    .. seealso:: `RFC 8738, section 5 <https://datatracker.ietf.org/doc/html/rfc8738#section-5>`_

    Parameters
    ----------
    challenge : :py:class:`~django_ca.models.AcmeChallenge`
        The challenge to validate.
    timeout: int, optional
        Timeout in seconds for the HTTP request.
    """
    if challenge.type != AcmeChallenge.TYPE_HTTP_01:
        raise ValueError("This function can only validate HTTP-01 challenges")

    decoded_token = challenge.encoded_token.decode("utf-8")
    expected = challenge.expected

    # RFC 8738, section 5: for IP identifiers the DNS resolution step is skipped and the IP
    # address is used directly. IPv6 addresses must be enclosed in brackets in the URL
    # (RFC 3986, section 3.2.2). The Host header is set automatically by the requests library
    # from the URL host component, satisfying RFC 8738 §5 / RFC 7230 §5.4.
    if challenge.auth.type == AcmeAuthorization.TYPE_IP:
        addr = ipaddress.ip_address(challenge.auth.value)
        if isinstance(addr, ipaddress.IPv6Address):
            url_host = f"[{addr}]"
        else:
            url_host = str(addr)
    else:
        url_host = challenge.auth.value

    url = f"http://{url_host}/.well-known/acme-challenge/{decoded_token}"

    try:
        with requests.get(url, timeout=1, stream=True, allow_redirects=False) as response:
            # Only fetch the response body if the status code is HTTP 200 (OK)
            if response.status_code == HTTPStatus.OK:
                # Only fetch the expected number of bytes to prevent a large file ending up in memory.
                # Fetch one extra byte (if available) to detect responses with trailing content.
                received = response.raw.read(len(expected) + 1, decode_content=True)
                return received == expected
    except Exception:  # pylint: disable=broad-except
        log.exception("Uncaught HTTP challenge validation exception.")

    return False


def validate_dns_01(challenge: AcmeChallenge, timeout: int = 1) -> bool:
    """Function to validate a DNS-01 challenge.

    .. seealso:: `RFC 8555, section 8.4 <https://datatracker.ietf.org/doc/html/rfc8555#section-8.4>`_

    Parameters
    ----------
    challenge : :py:class:`~django_ca.models.AcmeChallenge`
        The challenge to validate.
    timeout: int, optional
        Timeout for DNS queries.
    """
    if challenge.type != AcmeChallenge.TYPE_DNS_01:
        raise ValueError("This function can only validate DNS-01 challenges")

    # RFC 8738, section 7: dns-01 MUST NOT be used to validate IP identifiers.
    if challenge.auth.type == AcmeAuthorization.TYPE_IP:
        raise ValueError("dns-01 cannot be used to validate IP identifiers (RFC 8738, section 7)")

    domain = challenge.auth.value  # domain to validate

    # RFC 8555, section 8.4:
    #
    #   The client constructs the validation domain name by prepending the label "_acme-challenge"
    dns_name = f"_acme-challenge.{domain}"
    expected_token = challenge.expected  # the expected token in the DNS record
    log.info("DNS-01 validation of %s: Expect %s on %s", domain, expected_token.decode("utf-8"), dns_name)

    try:
        answers = resolver.resolve(dns_name, "TXT", lifetime=timeout, search=False)
    except resolver.NXDOMAIN:
        log.debug("TXT %s: record does not exist.", dns_name)
        return False
    except dns.exception.DNSException:
        log.exception("Uncaught DNS lookup exception.")
        return False

    # RFC 8555, section 8.4: "Verify that the contents of one of the TXT records match the digest value"
    for answer in answers:
        txt_data = answer.strings

        # A single TXT record can have multiple string values, even if rarely seen in practice
        for response_value in txt_data:
            if response_value == expected_token:
                return True

    return False


def validate_csr(
    csr: x509.CertificateSigningRequest, names_from_order: set[x509.DNSName | x509.IPAddress]
) -> None:
    """Validate that the CSR is usable to issue a certificate via ACME."""
    # Do not accept MD5 or SHA1 signatures
    hash_algorithm = csr.signature_hash_algorithm
    if hasattr(hashes, "MD5") and isinstance(hash_algorithm, hashes.MD5):
        raise AcmeBadCSR(message=f"{hash_algorithm.name}: Insecure hash algorithm.")
    if hasattr(hashes, "SHA1") and isinstance(hash_algorithm, hashes.SHA1):
        raise AcmeBadCSR(message=f"{hash_algorithm.name}: Insecure hash algorithm.")

    if csr.is_signature_valid is False:
        raise AcmeBadCSR(message="CSR signature is not valid.")

    # Perform sanity checks on the CSRs subject.
    # NOTE: certbot does *not* set any subject at all
    if csr.subject:
        # Perform basic sanity checks for subject. This also rules out multiple CommonName entries.
        try:
            check_name(csr.subject)
        except ValueError as ex:
            raise AcmeBadCSR(message=str(ex)) from ex

        # We allow a client setting a CommonName, but it *must* be part of the order.
        # The CN may refer to either a DNS name or an IP address (RFC 8738).
        common_name = next((attr for attr in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)), None)

        if common_name is not None:
            if isinstance(common_name.value, bytes):  # pragma: no cover  # CN is always string
                raise AcmeBadCSR(message="CommonName was not in order.")

            try:
                # Normalize to compressed form so the lookup against names_from_order
                # (which stores compressed values) is unambiguous (RFC 5952 §4).
                addr = ipaddress.ip_address(common_name.value)
                cn_general_name: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(addr.compressed))
            except ValueError:
                cn_general_name = x509.DNSName(common_name.value)

            if cn_general_name not in names_from_order:
                raise AcmeBadCSR(message="CommonName was not in order.")

    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound as ex:
        raise AcmeBadCSR(message="No subject alternative names found in CSR.") from ex

    # Normalize IP SANs to their compressed form so the set comparison against
    # names_from_order (which uses compressed values) is unambiguous.
    names_from_csr: set[x509.DNSName | x509.IPAddress] = set()
    for san_name in san_ext.value:
        if isinstance(san_name, x509.IPAddress) and isinstance(
            san_name.value, ipaddress.IPv4Address | ipaddress.IPv6Address
        ):
            names_from_csr.add(x509.IPAddress(ipaddress.ip_address(san_name.value.compressed)))
        elif isinstance(san_name, x509.DNSName):
            names_from_csr.add(san_name)
        else:
            raise AcmeBadCSR(message="Name with invalid type requested.")

    if names_from_order != names_from_csr:
        raise AcmeBadCSR(message="Names in CSR do not match.")
