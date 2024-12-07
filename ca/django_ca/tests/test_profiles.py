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

"""Test :py:mod:`django_ca.profiles`."""

import doctest
from datetime import datetime, timedelta, timezone as tz
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.constants import (
    CONFIGURABLE_EXTENSION_KEYS,
    END_ENTITY_CERTIFICATE_EXTENSION_KEYS,
    EXTENSION_DEFAULT_CRITICAL,
)
from django_ca.deprecation import RemovedInDjangoCA230Warning
from django_ca.key_backends.storages.models import StoragesUsePrivateKeyOptions
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import Profile, get_profile, profile, profiles
from django_ca.signals import pre_sign_cert
from django_ca.tests.base.assertions import assert_extensions
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.doctest import doctest_module
from django_ca.tests.base.mocks import mock_signal
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    cn,
    country,
    crl_distribution_points,
    distribution_point,
    dns,
    issuer_alternative_name,
    key_usage,
    ocsp_no_check,
    state,
    subject_alternative_name,
    subject_key_identifier,
    uri,
)

pytestmark = [pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])]
key_backend_options = StoragesUsePrivateKeyOptions(password=None)


@pytest.fixture
def doctest_globs(usable_root: CertificateAuthority) -> dict[str, Any]:
    """Fixture for context used in doctests."""
    return {
        "Profile": Profile,
        "get_profile": get_profile,
        "ca": usable_root,
        "ca_serial": usable_root.serial,
        "csr": CERT_DATA["root-cert"]["csr"]["parsed"],
    }


def create_cert(
    prof: Profile, ca: CertificateAuthority, csr: x509.CertificateSigningRequest, *args: Any, **kwargs: Any
) -> Certificate:
    """Shortcut to create a cert with the given profile."""
    cert = Certificate(ca=ca)
    cert.update_certificate(prof.create_cert(ca, key_backend_options, csr, *args, **kwargs))
    return cert


def test_doctests_module(doctest_globs: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
    """Run doctests for this module."""
    failures, *_tests = doctest_module("django_ca.profiles", globs=doctest_globs)
    assert failures == 0, f"{failures} doctests failed, see above for output."


def test_doctest_documentation(doctest_globs: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
    """Test python/profiles.rst."""
    failures, *_tests = doctest.testfile("../../../docs/source/python/profiles.rst", globs=doctest_globs)
    assert failures == 0, f"{failures} doctests failed, see above for output."


def test_get_profile() -> None:
    """Test the get_profile function()."""
    for name in model_settings.CA_PROFILES:
        prof = get_profile(name)
        assert name == prof.name

    prof = get_profile()
    assert prof.name == model_settings.CA_DEFAULT_PROFILE


def test_profiles_dict_key_access() -> None:
    """Some basic tests for the profiles proxy."""
    for name in model_settings.CA_PROFILES:
        prof = profiles[name]
        assert prof.name == name

    # Run a second time, b/c accessor also caches stuff sometimes
    for name in model_settings.CA_PROFILES:
        prof = profiles[name]
        assert prof.name == name


def test_profiles_with_none_key() -> None:
    """Test the ``None`` key."""
    assert profiles[None] == profile


def test_default_proxy() -> None:
    """Test using the default proxy."""
    assert profile.name == model_settings.CA_DEFAULT_PROFILE
    assert str(profile) == f"<DefaultProfile: {model_settings.CA_DEFAULT_PROFILE}>"
    assert repr(profile) == f"<DefaultProfile: {model_settings.CA_DEFAULT_PROFILE}>"

    assert profile == profiles[model_settings.CA_DEFAULT_PROFILE]


def test_default_proxy_eq() -> None:
    """Test equality for the default proxy."""
    assert profile == profile  # noqa: PLR0124  # what we're testing
    assert profile == profiles[model_settings.CA_DEFAULT_PROFILE]  # proxy is equal to default profile
    assert profile != ["not-equal"]  # we are not equal to arbitrary stuff


def test_eq() -> None:
    """Test profile equality."""
    prof = None
    for name in model_settings.CA_PROFILES:
        assert prof != profiles[name]
        prof = profiles[name]
        assert prof == prof  # noqa: PLR0124  # this is what we're testing
        assert prof is not None
        assert prof != -1


def test_str() -> None:
    """Test str()."""
    for name in model_settings.CA_PROFILES:
        assert str(profiles[name]) == f"<Profile: {name}>"


def test_repr() -> None:
    """Test repr()."""
    for name in model_settings.CA_PROFILES:
        assert repr(profiles[name]) == f"<Profile: {name}>"


def test_init_django_ca_values(subject: x509.Name) -> None:
    """Test passing serialized extensions leads to equal profiles."""
    prof1 = Profile("test", subject=subject, extensions={"ocsp_no_check": {}})
    prof2 = Profile("test", subject=subject, extensions={"ocsp_no_check": ocsp_no_check()})
    assert prof1 == prof2


def test_init_none_extension() -> None:
    """Test profiles that explicitly deactivate an extension."""
    prof = Profile("test", extensions={"ocsp_no_check": None})
    assert prof.extensions == {ExtensionOID.OCSP_NO_CHECK: None}
    assert prof.serialize()["clear_extensions"] == ["ocsp_no_check"]


def test_init_no_subject(settings: SettingsWrapper) -> None:
    """Test with no default subject."""
    # doesn't really occur in the wild, because model_settings updates CA_PROFILES with the default
    # subject. But it still seems sensible to support this
    settings.CA_DEFAULT_SUBJECT = ({"oid": "CN", "value": "testcase"},)
    prof = Profile("test")
    assert prof.subject == x509.Name([cn("testcase")])


def test_init_x509_subject(subject: x509.Name) -> None:
    """Test passing a cryptography subject."""
    prof = Profile("test", subject=subject)
    assert prof.subject == subject


def test_init_expires() -> None:
    """Test the `expire` parameter."""
    exp = timedelta(hours=3)
    prof = Profile("example", expires=exp)
    assert prof.expires == exp


def test_init_with_unsupported_extension() -> None:
    """Test creating a profile with an extension that should not be in a profile."""
    with pytest.raises(ValueError, match=r"^inhibit_any_policy: Extension cannot be used in a profile\.$"):
        # TYPEHINT NOTE: This is what we're testing.
        Profile("test", extensions={"inhibit_any_policy": None})  # type: ignore[dict-item]


def test_init_with_non_matching_extension() -> None:
    """Test creating a profile with an extension that should not be in a profile."""
    with pytest.raises(ValueError, match=r"^ocsp_no_check: .*Extension does not match key\.$"):
        # TYPEHINT NOTE: This is what we're testing.
        Profile("test", extensions={"ocsp_no_check": key_usage(key_agreement=True)})


def test_init_with_invalid_extension_type() -> None:
    """Test creating a profile with a completely invalid extension type."""
    with pytest.raises(TypeError, match=r"^Profile test, extension key_usage: True: Unsupported type$"):
        # TYPEHINT NOTE: This is what we're testing
        Profile(
            "test",
            extensions={
                # TYPEHINT NOTE: This is what we're testing.
                END_ENTITY_CERTIFICATE_EXTENSION_KEYS[ExtensionOID.KEY_USAGE]: True  # type: ignore[dict-item]
            },
        )


def test_create_cert(usable_root: CertificateAuthority, subject: x509.Name) -> None:
    """Create a certificate with minimal parameters."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    prof = Profile("example")
    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(prof, usable_root, csr, subject=subject, add_issuer_alternative_name=False)
    assert pre.call_count == 1
    assert_extensions(cert, [usable_root.get_authority_key_identifier_extension()])


def test_create_cert_with_alternative_values(usable_root: CertificateAuthority, hostname: str) -> None:
    """Test overriding most values."""
    usable_root.sign_issuer_alternative_name = issuer_alternative_name(uri("https://example.com"))
    usable_root.save()
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    country_name = x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")
    subject = x509.Name([country_name, x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    prof = Profile("example", subject=False)

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=x509.Name([country_name]),
            algorithm=hashes.SHA256(),
            not_after=timedelta(days=30),
            extensions=[subject_alternative_name(dns(hostname))],
        )
    assert pre.call_count == 1
    assert cert.cn == hostname
    assert cert.subject == subject
    assert_extensions(
        cert,
        [
            usable_root.get_authority_key_identifier_extension(),
            usable_root.sign_issuer_alternative_name,
            subject_alternative_name(dns(hostname)),
        ],
    )


def test_create_cert_with_overrides(usable_root: CertificateAuthority, hostname: str) -> None:
    """Test other overrides."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    san_francisco = x509.NameAttribute(oid=NameOID.LOCALITY_NAME, value="San Francisco")
    subject = x509.Name([country("US"), state("California"), cn(hostname)])
    expected_subject = x509.Name([country("US"), state("California"), san_francisco, cn(hostname)])

    prof = Profile(
        "example",
        subject=x509.Name([country("DE"), san_francisco]),
        add_crl_url=False,
        add_ocsp_url=False,
        add_issuer_url=False,
        add_issuer_alternative_name=False,
    )
    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(prof, usable_root, csr, subject=subject)
    assert pre.call_count == 1
    assert cert.subject == expected_subject
    assert cert.ca == usable_root

    assert_extensions(
        cert,
        [
            subject_key_identifier(cert),
            usable_root.get_authority_key_identifier_extension(),
            basic_constraints(),
        ],
        expect_defaults=False,
    )

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_crl_url=True,
            add_ocsp_url=True,
            add_issuer_url=True,
            add_issuer_alternative_name=True,
        )
    assert pre.call_count == 1
    assert cert.subject == expected_subject
    assert cert.ca == usable_root
    assert_extensions(
        cert,
        [
            usable_root.get_authority_key_identifier_extension(),
            basic_constraints(),
        ],
    )


def test_create_cert_with_none_extension(usable_root: CertificateAuthority, subject: x509.Name) -> None:
    """Test passing an extension that is removed by the profile."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    prof = Profile("example", extensions={"ocsp_no_check": None})

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(prof, usable_root, csr, subject=subject, extensions=[ocsp_no_check()])
    assert pre.call_count == 1
    assert ExtensionOID.OCSP_NO_CHECK not in cert.extensions


def test_create_cert_with_add_distribution_point_with_ca_crldp(
    usable_root: CertificateAuthority, subject: x509.Name
) -> None:
    """Pass a custom distribution point when creating the cert, which matches ca.crl_url."""
    prof = Profile("example")
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    # Add CRL Distribution Points extension to CA
    crl_url = "https://crl.ca.example.com"
    usable_root.sign_crl_distribution_points = crl_distribution_points(distribution_point([uri(crl_url)]))
    usable_root.save()

    added_crldp = crl_distribution_points(distribution_point([uri(crl_url)]))

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_crl_url=True,
            add_ocsp_url=False,
            add_issuer_url=False,
            add_issuer_alternative_name=False,
            extensions=[added_crldp],
        )
    assert pre.call_count == 1
    ski = x509.SubjectKeyIdentifier.from_public_key(cert.pub.loaded.public_key())

    assert_extensions(
        cert,
        [
            usable_root.get_authority_key_identifier_extension(),
            basic_constraints(),
            x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
            added_crldp,
        ],
        expect_defaults=False,
    )


def test_create_cert_with_with_algorithm(usable_root: CertificateAuthority, subject: x509.Name) -> None:
    """Test a profile that manually overrides the algorithm."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    prof = Profile("example", algorithm="SHA-512")

    # Make sure that algorithm does not match what is the default profile above, so that we can test it
    assert isinstance(usable_root.algorithm, hashes.SHA256)

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_crl_url=True,
            add_ocsp_url=False,
            add_issuer_url=False,
            add_issuer_alternative_name=False,
        )
    assert pre.call_count == 1
    assert isinstance(cert.algorithm, hashes.SHA512)


def test_create_cert_with_issuer_alternative_name_override(
    usable_root: CertificateAuthority, subject: x509.Name
) -> None:
    """Pass a custom Issuer Alternative Name which overwrites the CA value."""
    prof = Profile("example")
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    # Add CRL url to CA
    usable_root.sign_issuer_alternative_name = issuer_alternative_name(uri("https://ian.ca.example.com"))
    usable_root.save()

    added_ian_uri = uri("https://ian.cert.example.com")

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_crl_url=False,
            add_ocsp_url=False,
            add_issuer_url=False,
            add_issuer_alternative_name=True,
            extensions=[issuer_alternative_name(added_ian_uri)],
        )
    assert pre.call_count == 1
    ski = x509.SubjectKeyIdentifier.from_public_key(cert.pub.loaded.public_key())

    assert_extensions(
        cert,
        [
            usable_root.get_authority_key_identifier_extension(),
            basic_constraints(),
            x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
            issuer_alternative_name(added_ian_uri),
        ],
        expect_defaults=False,
    )


def test_create_cert_with_merge_authority_information_access_existing_values(
    usable_root: CertificateAuthority, subject: x509.Name
) -> None:
    """Pass a custom distribution point when creating the cert, which matches ca.crl_url."""
    prof = Profile("example")
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    # Set Authority Information Access extesion
    usable_root.sign_authority_information_access = authority_information_access(
        ca_issuers=[uri("https://issuer.ca.example.com")], ocsp=[uri("https://ocsp.ca.example.com")]
    )
    usable_root.save()

    cert_issuers = uri("https://issuer.cert.example.com")
    cert_issuers2 = uri("https://issuer2.cert.example.com")
    cert_ocsp = uri("https://ocsp.cert.example.com")

    added_aia = authority_information_access(ca_issuers=[cert_issuers, cert_issuers2], ocsp=[cert_ocsp])

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_crl_url=False,
            add_ocsp_url=True,
            add_issuer_url=True,
            add_issuer_alternative_name=False,
            extensions=[added_aia],
        )
    assert pre.call_count == 1

    ski = x509.SubjectKeyIdentifier.from_public_key(cert.pub.loaded.public_key())

    assert_extensions(
        cert,
        [
            usable_root.get_authority_key_identifier_extension(),
            basic_constraints(),
            x509.Extension(oid=ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False, value=ski),
            authority_information_access(
                ca_issuers=[cert_issuers, cert_issuers2],
                ocsp=[cert_ocsp],
            ),
        ],
        expect_defaults=False,
    )


def test_create_cert_with_extension_as_cryptography(
    usable_root: CertificateAuthority, subject: x509.Name
) -> None:
    """Test with a profile that has cryptography extensions."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    prof = Profile("example", extensions={CONFIGURABLE_EXTENSION_KEYS[ExtensionOID.OCSP_NO_CHECK]: {}})
    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_issuer_alternative_name=False,
            extensions=[ocsp_no_check()],
        )
    assert pre.call_count == 1
    assert_extensions(
        cert,
        [usable_root.get_authority_key_identifier_extension(), basic_constraints(), ocsp_no_check()],
    )


def test_create_cert_with_extension_overrides(usable_root: CertificateAuthority, subject: x509.Name) -> None:
    """Test that all extensions can be overwritten when creating a new certificate."""
    # Profile with extensions (will be overwritten by the command line).
    prof = Profile(
        "example",
        extensions={
            CONFIGURABLE_EXTENSION_KEYS[
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ]: authority_information_access(
                ocsp=[uri("http://ocsp.example.com/profile")],
                ca_issuers=[uri("http://issuer.example.com/issuer")],
            )
        },
    )

    usable_root.sign_authority_information_access = authority_information_access(
        ca_issuers=[uri("http://issuer.example.com/issuer")], ocsp=[uri("http://ocsp.example.com/ca")]
    )
    usable_root.save()

    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    expected_authority_information_access = authority_information_access(
        ocsp=[uri("http://ocsp.example.com/expected")],
        ca_issuers=[uri("http://issuer.example.com/expected")],
    )

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_issuer_alternative_name=False,
            add_issuer_url=True,
            add_ocsp_url=True,
            extensions=[expected_authority_information_access],
        )
    assert pre.call_count == 1

    extensions = cert.extensions
    assert extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == expected_authority_information_access


def test_create_cert_with_partial_authority_information_access_override(
    usable_root: CertificateAuthority, subject: x509.Name
) -> None:
    """Test partial overwriting of the Authority Information Access extension."""
    prof = Profile(
        "example",
        extensions={
            CONFIGURABLE_EXTENSION_KEYS[
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ]: authority_information_access(
                ocsp=[uri("http://ocsp.example.com/profile")],
                ca_issuers=[uri("http://issuer.example.com/issuer")],
            )
        },
    )
    assert usable_root.sign_authority_information_access is not None
    ca_issuers_url = next(
        ad
        for ad in usable_root.sign_authority_information_access.value
        if ad.access_method == AuthorityInformationAccessOID.CA_ISSUERS
    ).access_location
    ca_ocsp_url = next(
        ad
        for ad in usable_root.sign_authority_information_access.value
        if ad.access_method == AuthorityInformationAccessOID.OCSP
    ).access_location
    usable_root.save()

    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    # Only pass an OCSP responder
    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_issuer_alternative_name=False,
            add_issuer_url=True,
            add_ocsp_url=True,
            extensions=[
                authority_information_access(
                    ocsp=[uri("http://ocsp.example.com/expected")],
                )
            ],
        )
    assert pre.call_count == 1

    extensions = cert.extensions
    assert extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        ocsp=[uri("http://ocsp.example.com/expected")], ca_issuers=[ca_issuers_url]
    )

    # Only pass an CA issuer
    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(
            prof,
            usable_root,
            csr,
            subject=subject,
            add_issuer_alternative_name=False,
            add_issuer_url=True,
            add_ocsp_url=True,
            extensions=[
                authority_information_access(
                    ca_issuers=[uri("http://issuer.example.com/expected")],
                )
            ],
        )
    assert pre.call_count == 1

    extensions = cert.extensions
    assert extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        ocsp=[ca_ocsp_url], ca_issuers=[uri("http://issuer.example.com/expected")]
    )


def test_create_cert_with_no_cn_no_san(usable_root: CertificateAuthority) -> None:
    """Test creating a cert with no cn in san."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]

    prof = Profile("example")
    msg = r"^Must name at least a CN or a subjectAlternativeName\.$"
    with mock_signal(pre_sign_cert) as pre, pytest.raises(ValueError, match=msg):
        create_cert(prof, usable_root, csr, subject=None)
    assert pre.call_count == 0
    assert Certificate.objects.filter(ca=usable_root).count() == 0


def test_create_cert_with_no_valid_cn_in_san(usable_root: CertificateAuthority) -> None:
    """Test what happens when the SAN has nothing usable as CN."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    prof = Profile("example", extensions={CONFIGURABLE_EXTENSION_KEYS[ExtensionOID.OCSP_NO_CHECK]: {}})
    san = subject_alternative_name(x509.RegisteredID(ExtensionOID.OCSP_NO_CHECK))

    with mock_signal(pre_sign_cert) as pre:
        cert = create_cert(prof, usable_root, csr, extensions=[san])
    assert pre.call_count == 1
    assert cert.subject == model_settings.CA_DEFAULT_SUBJECT


def test_create_cert_with_deprecated_expires(usable_root: CertificateAuthority, subject: x509.Name) -> None:
    """Create a certificate with the deprecated expires parameter."""
    not_after = datetime.now(tz=tz.utc) + timedelta(days=12)
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    warning = (
        r"^Argument `expires` is deprecated and will be removed in django-ca 2.3, use `not_after` instead\.$"
    )

    prof = Profile("example")
    with pytest.warns(RemovedInDjangoCA230Warning, match=warning):
        cert = create_cert(prof, usable_root, csr, subject=subject, expires=not_after)
    assert cert.not_after == not_after
    assert cert.pub.loaded.not_valid_after_utc == not_after


def test_create_cert_with_not_after_and_deprecated_expires(
    usable_root: CertificateAuthority, subject: x509.Name
) -> None:
    """Create a certificate with the not_after AND deprecated expires parameter, which is an error."""
    not_after = datetime.now(tz=tz.utc) + timedelta(days=12)
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    warning = (
        r"^Argument `expires` is deprecated and will be removed in django-ca 2.3, use `not_after` instead\.$"
    )
    error = r"^`not_before` and `expires` cannot both be set\.$"

    prof = Profile("example")
    with pytest.warns(RemovedInDjangoCA230Warning, match=warning), pytest.raises(ValueError, match=error):
        create_cert(prof, usable_root, csr, subject=subject, expires=not_after, not_after=not_after)


def test_create_cert_with_unknown_signature_hash_algorithm() -> None:
    """Test passing an unknown hash algorithm."""
    with pytest.raises(ValueError, match=r"^foo: Unknown hash algorithm\.$"):
        Profile("wrong-algorithm", algorithm="foo")  # type: ignore[arg-type]


def test_create_cert_with_no_valid_subject(settings: SettingsWrapper, root: CertificateAuthority) -> None:
    """Test case where no subject at all could be determined."""
    csr = CERT_DATA["child-cert"]["csr"]["parsed"]
    settings.CA_DEFAULT_SUBJECT = None
    prof = Profile("test")
    with pytest.raises(ValueError, match=r"^Cannot determine subject for certificate\.$"):
        create_cert(prof, root, csr)


def test_create_cert_with_unsupported_extension(root: CertificateAuthority) -> None:
    """Test creating a certificate with an unsupported extension."""
    prof = Profile("test")
    with pytest.raises(ValueError, match=r"Extension cannot be set when creating a certificate\.$"):
        prof.create_cert(
            root,
            key_backend_options,
            CERT_DATA["root-cert"]["csr"]["parsed"],
            extensions=[
                # TYPEHINT NOTE: This is what we're testing.
                basic_constraints(ca=False)  # type: ignore[list-item]
            ],
        )


def test_serialize() -> None:
    """Test profile serialization."""
    desc = "foo bar"
    key_usage_items = ["digital_signature"]
    prof = Profile(
        "test",
        algorithm="SHA-512",
        description=desc,
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]),
        extensions={
            CONFIGURABLE_EXTENSION_KEYS[ExtensionOID.KEY_USAGE]: {"value": key_usage_items},
            CONFIGURABLE_EXTENSION_KEYS[ExtensionOID.EXTENDED_KEY_USAGE]: None,
        },
    )
    assert prof.serialize() == {
        "name": "test",
        "algorithm": "SHA-512",
        "subject": [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}],
        "description": desc,
        "clear_extensions": ["extended_key_usage"],
        "extensions": [
            {
                "type": "key_usage",
                "value": key_usage_items,
                "critical": EXTENSION_DEFAULT_CRITICAL[ExtensionOID.KEY_USAGE],
            },
        ],
    }
