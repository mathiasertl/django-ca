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

"""TestCase base classes that preload some data and add common helper methods."""

import inspect
import json
import os
import re
import shutil
import tempfile
import typing
from contextlib import contextmanager
from datetime import datetime, timedelta
from unittest.mock import patch

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding

from django.conf import settings
from django.test.utils import override_settings

from django_ca import constants
from django_ca.extensions import parse_extension
from django_ca.profiles import profiles
from django_ca.typehints import PrivateKeyTypes
from django_ca.utils import add_colons, ca_storage

FuncTypeVar = typing.TypeVar("FuncTypeVar", bound=typing.Callable[..., typing.Any])
KeyDict = typing.TypedDict("KeyDict", {"pem": str, "parsed": PrivateKeyTypes})
CsrDict = typing.TypedDict("CsrDict", {"pem": str, "parsed": x509.CertificateSigningRequest, "der": bytes})
_PubDict = typing.TypedDict("_PubDict", {"pem": str, "parsed": x509.Certificate})


# Regex used by certbot to split PEM-encodied certificate chains/bundles as of 2022-01-23. See also:
# 	https://github.com/certbot/certbot/blob/master/certbot/certbot/crypto_util.py
CERT_PEM_REGEX = re.compile(
    b"""-----BEGIN CERTIFICATE-----\r?
.+?\r?
-----END CERTIFICATE-----\r?
""",
    re.DOTALL,  # DOTALL (/s) because the base64text may include newlines
)


# pylint: disable-next=inherit-non-class; False positive
class PubDict(_PubDict, total=False):  # pylint: disable=missing-class-docstring
    der: bytes


def _load_key(data: typing.Dict[typing.Any, typing.Any]) -> KeyDict:
    basedir = data.get("basedir", settings.FIXTURES_DIR)
    path = os.path.join(basedir, data["key_filename"])

    with open(path, "rb") as stream:
        raw = stream.read()

    parsed = serialization.load_pem_private_key(raw, password=data.get("password"))
    return {
        "pem": raw.decode("utf-8"),
        "parsed": parsed,  # type: ignore[typeddict-item]  # we do not support all key types
    }


def _load_csr(data: typing.Dict[typing.Any, typing.Any]) -> CsrDict:
    basedir = data.get("basedir", settings.FIXTURES_DIR)
    path = os.path.join(basedir, data["csr_filename"])

    with open(path, "rb") as stream:
        raw = stream.read().strip()

    parsed = x509.load_pem_x509_csr(raw)
    return {
        "pem": raw.decode("utf-8"),
        "parsed": parsed,
        "der": parsed.public_bytes(Encoding.DER),
    }


def _load_pub(data: typing.Dict[typing.Any, typing.Any]) -> PubDict:
    basedir = data.get("basedir", settings.FIXTURES_DIR)
    path = os.path.join(basedir, data["pub_filename"])

    with open(path, "rb") as stream:
        pem = stream.read().replace(b"\r\n", b"\n")

    pub_data: PubDict = {
        "pem": pem.decode("utf-8"),
        "parsed": x509.load_pem_x509_certificate(pem),
    }

    if data.get("pub_der_filename"):
        der_path = os.path.join(basedir, data["pub_der_filename"])
        with open(der_path, "rb") as stream:
            der = stream.read().replace(b"\r\n", b"\n")
        pub_data["der"] = der
        # Fails for alt-extensions since alternative AKI was added
        # pub_data['der_parsed'] = x509.load_der_x509_certificate(der),

    return pub_data


cryptography_version = tuple(int(t) for t in cryptography.__version__.split(".")[:2])

with open(os.path.join(settings.FIXTURES_DIR, "cert-data.json"), encoding="utf-8") as cert_data_stream:
    _fixture_data = json.load(cert_data_stream)
certs = _fixture_data.get("certs")

# Update some data from contrib (data is not in cert-data.json, since we don't generate them)
certs["multiple_ous"] = {
    "name": "multiple_ous",
    "cn": "",
    "key_filename": False,
    "csr_filename": False,
    "pub_filename": os.path.join("contrib", "multiple_ous_and_no_ext.pem"),
    "key_type": "RSA",
    "cat": "contrib",
    "type": "cert",
    "valid_from": "1998-05-18 00:00:00",
    "valid_until": "2028-08-01 23:59:59",
    "ca": "root",
    "serial": "7DD9FE07CFA81EB7107967FBA78934C6",
    "hpkp": "AjyBzOjnxk+pQtPBUEhwfTXZu1uH9PVExb8bxWQ68vo=",
    "md5": "A2:33:9B:4C:74:78:73:D4:6C:E7:C1:F3:8D:CB:5C:E9",
    "sha1": "85:37:1C:A6:E5:50:14:3D:CE:28:03:47:1B:DE:3A:09:E8:F8:77:0F",
    "sha256": "83:CE:3C:12:29:68:8A:59:3D:48:5F:81:97:3C:0F:91:95:43:1E:DA:37:CC:5E:36:43:0E:79:C7:A8:88:63:8B",  # NOQA
    "sha512": "86:20:07:9F:8B:06:80:43:44:98:F6:7A:A4:22:DE:7E:2B:33:10:9B:65:72:79:C4:EB:F3:F3:0F:66:C8:6E:89:1D:4C:6C:09:1C:83:45:D1:25:6C:F8:65:EB:9A:B9:50:8F:26:A8:85:AE:3A:E4:8A:58:60:48:65:BB:44:B6:CE",  # NOQA
}
certs["cloudflare_1"] = {
    "name": "cloudflare_1",
    "cn": "sni24142.cloudflaressl.com",
    "key_filename": False,
    "csr_filename": False,
    "pub_filename": os.path.join("contrib", "cloudflare_1.pem"),
    "cat": "contrib",
    "type": "cert",
    "key_type": "EC",
    "valid_from": "2018-07-18 00:00:00",
    "valid_until": "2019-01-24 23:59:59",
    "ca": "root",
    "serial": "92529ABD85F0A6A4D6C53FD1C91011C1",
    "hpkp": "bkunFfRSda4Yhz7UlMUaalgj0Gcus/9uGVp19Hceczg=",
    "md5": "D6:76:03:E9:4F:3B:B0:F1:F7:E3:A1:40:80:8E:F0:4A",
    "sha1": "71:BD:B8:21:80:BD:86:E8:E5:F4:2B:6D:96:82:B2:EF:19:53:ED:D3",
    "sha256": "1D:8E:D5:41:E5:FF:19:70:6F:65:86:A9:A3:6F:DF:DE:F8:A0:07:22:92:71:9E:F1:CD:F8:28:37:39:02:E0:A1",  # NOQA
    "sha512": "FF:03:1B:8F:11:E8:A7:FF:91:4F:B9:97:E9:97:BC:77:37:C1:A7:69:86:F3:7C:E3:BB:BB:DF:A6:4F:0E:3C:C0:7F:B5:BC:CC:BD:0A:D5:EF:5F:94:55:E9:FF:48:41:34:B8:11:54:57:DD:90:85:41:2E:71:70:5E:FA:BA:E6:EA",  # NOQA
    "authority_information_access": {
        "critical": False,
        "value": {
            "issuers": ["URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt"],
            "ocsp": ["URI:http://ocsp.comodoca4.com"],
        },
    },
    "authority_key_identifier": {
        "critical": False,
        "value": "40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96",
    },
    "basic_constraints": {
        "critical": True,
        "value": {"ca": False},
    },
    "crl_distribution_points": {
        "value": [
            {
                "full_name": [
                    "URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl",
                ],
            }
        ],
        "critical": False,
    },
    "extended_key_usage": {
        "critical": False,
        "value": ["serverAuth", "clientAuth"],
    },
    "key_usage": {
        "critical": True,
        "value": ["digital_signature"],
    },
    "precert_poison": {"critical": True},
    "subject_alternative_name": {
        "value": [
            "DNS:sni24142.cloudflaressl.com",
            "DNS:*.animereborn.com",
            "DNS:*.beglideas.ga",
            "DNS:*.chroma.ink",
            "DNS:*.chuckscleanings.ga",
            "DNS:*.clipvuigiaitris.ga",
            "DNS:*.cmvsjns.ga",
            "DNS:*.competegraphs.ga",
            "DNS:*.consoleprints.ga",
            "DNS:*.copybreezes.ga",
            "DNS:*.corphreyeds.ga",
            "DNS:*.cyanigees.ga",
            "DNS:*.dadpbears.ga",
            "DNS:*.dahuleworldwides.ga",
            "DNS:*.dailyopeningss.ga",
            "DNS:*.daleylexs.ga",
            "DNS:*.danajweinkles.ga",
            "DNS:*.dancewthyogas.ga",
            "DNS:*.darkmoosevpss.ga",
            "DNS:*.daurat.com.ar",
            "DNS:*.deltaberg.com",
            "DNS:*.drjahanobgyns.ga",
            "DNS:*.drunkgirliess.ga",
            "DNS:*.duhiepkys.ga",
            "DNS:*.dujuanjsqs.ga",
            "DNS:*.dumbiseasys.ga",
            "DNS:*.dumpsoftdrinkss.ga",
            "DNS:*.dunhavenwoodss.ga",
            "DNS:*.durabiliteas.ga",
            "DNS:*.duxmangroups.ga",
            "DNS:*.dvpdrivewayss.ga",
            "DNS:*.dwellwizes.ga",
            "DNS:*.dwwkouis.ga",
            "DNS:*.entertastic.com",
            "DNS:*.estudiogolber.com.ar",
            "DNS:*.letsretro.team",
            "DNS:*.maccuish.org.uk",
            "DNS:*.madamsquiggles.com",
            "DNS:*.sftw.ninja",
            "DNS:*.spangenberg.io",
            "DNS:*.timmutton.com.au",
            "DNS:*.wyomingsexbook.com",
            "DNS:*.ych.bid",
            "DNS:animereborn.com",
            "DNS:beglideas.ga",
            "DNS:chroma.ink",
            "DNS:chuckscleanings.ga",
            "DNS:clipvuigiaitris.ga",
            "DNS:cmvsjns.ga",
            "DNS:competegraphs.ga",
            "DNS:consoleprints.ga",
            "DNS:copybreezes.ga",
            "DNS:corphreyeds.ga",
            "DNS:cyanigees.ga",
            "DNS:dadpbears.ga",
            "DNS:dahuleworldwides.ga",
            "DNS:dailyopeningss.ga",
            "DNS:daleylexs.ga",
            "DNS:danajweinkles.ga",
            "DNS:dancewthyogas.ga",
            "DNS:darkmoosevpss.ga",
            "DNS:daurat.com.ar",
            "DNS:deltaberg.com",
            "DNS:drjahanobgyns.ga",
            "DNS:drunkgirliess.ga",
            "DNS:duhiepkys.ga",
            "DNS:dujuanjsqs.ga",
            "DNS:dumbiseasys.ga",
            "DNS:dumpsoftdrinkss.ga",
            "DNS:dunhavenwoodss.ga",
            "DNS:durabiliteas.ga",
            "DNS:duxmangroups.ga",
            "DNS:dvpdrivewayss.ga",
            "DNS:dwellwizes.ga",
            "DNS:dwwkouis.ga",
            "DNS:entertastic.com",
            "DNS:estudiogolber.com.ar",
            "DNS:letsretro.team",
            "DNS:maccuish.org.uk",
            "DNS:madamsquiggles.com",
            "DNS:sftw.ninja",
            "DNS:spangenberg.io",
            "DNS:timmutton.com.au",
            "DNS:wyomingsexbook.com",
            "DNS:ych.bid",
        ]
    },
    "subject_key_identifier": {
        "critical": False,
        "value": "05:86:D8:B4:ED:A9:7E:23:EE:2E:E7:75:AA:3B:2C:06:08:2A:93:B2",
    },
    "certificate_policies": {
        "value": [
            {
                "policy_identifier": "1.3.6.1.4.1.6449.1.2.2.7",
                "policy_qualifiers": ["https://secure.comodo.com/CPS"],
            },
            {"policy_identifier": "2.23.140.1.2.1"},
        ],
        "critical": False,
    },
}

SPHINX_FIXTURES_DIR = os.path.join(os.path.dirname(settings.BASE_DIR), "docs", "source", "_files")
for cert_name, cert_data in certs.items():
    cert_data["serial_colons"] = add_colons(cert_data["serial"])
    if cert_data.get("password"):
        cert_data["password"] = cert_data["password"].encode("utf-8")
    if cert_data["cat"] == "sphinx-contrib":
        cert_data["basedir"] = os.path.join(SPHINX_FIXTURES_DIR, cert_data["type"])

    if cert_data["type"] == "ca":
        cert_data.setdefault("children", [])

    # Load data from files
    if cert_data["key_filename"] is not False:
        cert_data["key"] = _load_key(cert_data)
    if cert_data["csr_filename"] is not False:
        cert_data["csr"] = _load_csr(cert_data)
    cert_data["pub"] = _load_pub(cert_data)

    # parse some data from the dict
    cert_data["valid_from"] = datetime.strptime(cert_data["valid_from"], "%Y-%m-%d %H:%M:%S")
    cert_data["valid_until"] = datetime.strptime(cert_data["valid_until"], "%Y-%m-%d %H:%M:%S")
    cert_data["valid_from_short"] = cert_data["valid_from"].strftime("%Y-%m-%d %H:%M")
    cert_data["valid_until_short"] = cert_data["valid_until"].strftime("%Y-%m-%d %H:%M")

    cert_data["ocsp-serial"] = cert_data["serial"].replace(":", "")
    cert_data["ocsp-expires"] = cert_data["valid_until"].strftime("%y%m%d%H%M%SZ")

    # parse extensions
    for ext_key in constants.EXTENSION_KEY_OIDS:
        if cert_data.get(ext_key):
            cert_data[f"{ext_key}_serialized"] = cert_data[ext_key]

            # extensions are not parsable, see also: https://github.com/pyca/cryptography/issues/7824
            if ext_key not in (
                "precertificate_signed_certificate_timestamps",
                "signed_certificate_timestamps",
            ):
                cert_data[ext_key] = parse_extension(ext_key, cert_data[ext_key])

# Calculate some fixed timestamps that we reuse throughout the tests
timestamps = {
    "base": datetime.strptime(_fixture_data["timestamp"], "%Y-%m-%d %H:%M:%S"),
    "before_everything": datetime(1990, 1, 1),
}
timestamps["before_cas"] = timestamps["base"] - timedelta(days=1)
timestamps["before_child"] = timestamps["base"] + timedelta(days=1)
timestamps["after_child"] = timestamps["base"] + timedelta(days=4)
timestamps["ca_certs_valid"] = timestamps["base"] + timedelta(days=7)
timestamps["profile_certs_valid"] = timestamps["base"] + timedelta(days=12)

# When creating fixutres, latest valid_from from of any generated cert is 20 days, we need to be after that
timestamps["everything_valid"] = timestamps["base"] + timedelta(days=23)
timestamps["cas_expired"] = timestamps["base"] + timedelta(days=731, seconds=3600)
timestamps["ca_certs_expiring"] = certs["root-cert"]["valid_until"] - timedelta(days=3)
timestamps["ca_certs_expired"] = certs["root-cert"]["valid_until"] + timedelta(seconds=3600)
timestamps["profile_certs_expired"] = certs["profile-server"]["valid_until"] + timedelta(seconds=3600)
timestamps["everything_expired"] = timestamps["base"] + timedelta(days=365 * 20)
ocsp_data = _fixture_data["ocsp"]


def dns(name: str) -> x509.DNSName:  # just a shortcut
    """Shortcut to get a :py:class:`cg:cryptography.x509.DNSName`."""
    return x509.DNSName(name)


def uri(url: str) -> x509.UniformResourceIdentifier:  # just a shortcut
    """Shortcut to get a :py:class:`cg:cryptography.x509.UniformResourceIdentifier`."""
    return x509.UniformResourceIdentifier(url)


def rdn(
    name: typing.Iterable[typing.Tuple[x509.ObjectIdentifier, str]]
) -> x509.RelativeDistinguishedName:  # just a shortcut
    """Shortcut to get a :py:class:`cg:cryptography.x509.RelativeDistinguishedName`."""
    return x509.RelativeDistinguishedName([x509.NameAttribute(*t) for t in name])


@contextmanager
def mock_cadir(path: str) -> typing.Iterator[None]:
    """Contextmanager to set the CA_DIR to a given path without actually creating it."""
    with override_settings(CA_DIR=path), patch.object(ca_storage, "location", path), patch.object(
        ca_storage, "_location", path
    ):
        yield


class override_tmpcadir(override_settings):  # pylint: disable=invalid-name; in line with parent class
    """Sets the CA_DIR directory to a temporary directory.

    .. NOTE: This also takes any additional settings.
    """

    def __call__(self, test_func: FuncTypeVar) -> FuncTypeVar:
        if not inspect.isfunction(test_func):
            raise ValueError("Only functions can use override_tmpcadir()")
        return super().__call__(test_func)  # type: ignore[no-any-return]

    def enable(self) -> None:
        self.options["CA_DIR"] = tempfile.mkdtemp()

        # copy CAs
        for filename in [v["key_filename"] for v in certs.values() if v["key_filename"] is not False]:
            shutil.copy(os.path.join(settings.FIXTURES_DIR, filename), self.options["CA_DIR"])

        # Copy OCSP public key (required for OCSP tests)
        shutil.copy(
            os.path.join(settings.FIXTURES_DIR, certs["profile-ocsp"]["pub_filename"]), self.options["CA_DIR"]
        )

        # pylint: disable=attribute-defined-outside-init
        self.mock = patch.object(ca_storage, "location", self.options["CA_DIR"])
        self.mock_ = patch.object(ca_storage, "_location", self.options["CA_DIR"])
        # pylint: enable=attribute-defined-outside-init

        # Reset profiles, so that they are loaded again on first access
        profiles._reset()  # pylint: disable=protected-access

        self.mock.start()
        self.mock_.start()

        super().enable()

    def disable(self) -> None:
        super().disable()
        self.mock.stop()
        self.mock_.stop()
        shutil.rmtree(self.options["CA_DIR"])


__all__ = ("override_settings",)
