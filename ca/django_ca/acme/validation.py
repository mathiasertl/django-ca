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

import logging

import dns.exception
from dns import resolver

from django_ca.models import AcmeChallenge

log = logging.getLogger(__name__)


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
    except dns.exception.DNSException as ex:
        log.exception(ex)
        return False

    # RFC 8555, section 8.4: "Verify that the contents of one of the TXT records match the digest value"
    for answer in answers:
        txt_data = answer.strings

        # A single TXT record can have multiple string values, even if rarely seen in practice
        for response_value in txt_data:
            if response_value == expected_token:
                return True

    return False
