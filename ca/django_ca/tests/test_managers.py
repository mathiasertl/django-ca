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

"""TestCases for various model managers."""

from datetime import datetime, timedelta, timezone as tz
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import ExtensionOID, NameOID

from django.urls import reverse

import pytest
from pytest_django.fixtures import SettingsWrapper

from django_ca.conf import model_settings
from django_ca.constants import ExtendedKeyUsageOID
from django_ca.key_backends.storages import StoragesBackend
from django_ca.key_backends.storages.models import (
    StoragesCreatePrivateKeyOptions,
    StoragesUsePrivateKeyOptions,
)
from django_ca.models import Certificate, CertificateAuthority
from django_ca.profiles import profiles
from django_ca.querysets import CertificateAuthorityQuerySet, CertificateQuerySet
from django_ca.tests.base.assertions import (
    assert_ca_properties,
    assert_certificate,
    assert_create_ca_signals,
    assert_create_cert_signals,
    assert_extensions,
    assert_improperly_configured,
)
from django_ca.tests.base.constants import CERT_DATA, TIMESTAMPS
from django_ca.tests.base.utils import (
    authority_information_access,
    basic_constraints,
    crl_distribution_points,
    distribution_point,
    dns,
    extended_key_usage,
    key_usage,
    name_constraints,
    ocsp_no_check,
    precert_poison,
    rdn,
    tls_feature,
    uri,
)
from django_ca.typehints import CertificateExtension


def assert_intermediate_extensions(parent: CertificateAuthority, intermediate: CertificateAuthority) -> None:
    """Test values extensions based on a parent CA."""
    host = model_settings.CA_DEFAULT_HOSTNAME  # shortcut
    url_kwargs = {"serial": parent.serial}
    expected_issuers = [uri(f"http://{host}{reverse('django_ca:issuer', kwargs=url_kwargs)}")]
    expected_ocsp = [uri(f"http://{host}{reverse('django_ca:ocsp-ca-post', kwargs=url_kwargs)}")]
    assert intermediate.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        ca_issuers=expected_issuers, ocsp=expected_ocsp
    )

    assert intermediate.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri(f"http://{host}{reverse('django_ca:ca-crl', kwargs=url_kwargs)}")])
    )


key_backend_options = StoragesCreatePrivateKeyOptions(
    key_type="RSA", password=None, path=Path("ca"), key_size=1024
)
parent_key_backend_options = StoragesUsePrivateKeyOptions(password=None)


@pytest.mark.django_db
def test_init(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Create the most basic possible CA."""
    expires = datetime.now(tz=tz.utc) + timedelta(days=10)
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(ca_name, key_backend, key_backend_options, subject, expires)
    assert_ca_properties(ca, ca_name)
    assert_certificate(ca, subject)

    # Make sure that extensions related to revocation are **not** present, they make no sense for root CAs.
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS not in ca.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in ca.extensions


@pytest.mark.django_db
def test_init_with_dsa(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Create a DSA-based CA."""
    expires = datetime.now(tz=tz.utc) + timedelta(days=10)
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name, key_backend, key_backend_options, subject, expires, key_type="DSA"
        )
    assert_ca_properties(ca, ca_name, private_key_type=dsa.DSAPrivateKey)
    assert_certificate(ca, subject, algorithm=hashes.SHA256)


@pytest.mark.django_db
def test_init_with_password(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Create a CA with a password."""
    test_key_backend_options = StoragesCreatePrivateKeyOptions(
        password=b"password", path=Path("ca"), key_type="RSA", key_size=1024
    )
    test_parent_key_backend_options = StoragesUsePrivateKeyOptions(password=b"password")
    expires = datetime.now(tz=tz.utc) + timedelta(days=10)
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name, key_backend, test_key_backend_options, subject, expires
        )
    assert_ca_properties(ca, ca_name, password=b"password")
    assert_certificate(ca, subject)

    # Test that we can re-load the private key with the password
    reloaded_ca: CertificateAuthority = CertificateAuthority.objects.get(id=ca.id)
    private_key = reloaded_ca.key_backend.get_key(  # type: ignore[attr-defined]
        reloaded_ca, test_parent_key_backend_options
    )
    assert isinstance(private_key, rsa.RSAPrivateKey)


def test_init_intermediate(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, usable_root: CertificateAuthority
) -> None:
    """Create an intermediate CA."""
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_root,
            use_parent_private_key_options=parent_key_backend_options,
        )
    assert_ca_properties(ca, ca_name, parent=usable_root)
    assert_certificate(ca, subject, signer=usable_root)
    assert_intermediate_extensions(usable_root, ca)


def test_init_grandchild(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, usable_child: CertificateAuthority
) -> None:
    """Create a third-level CA."""
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_child,
            use_parent_private_key_options=parent_key_backend_options,
        )
    assert_ca_properties(ca, ca_name, parent=usable_child)
    assert_certificate(ca, subject, signer=usable_child)
    assert_intermediate_extensions(usable_child, ca)


@pytest.mark.django_db
def test_openssh_ca(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Test OpenSSH CA support."""
    ca_key_backend_options = StoragesCreatePrivateKeyOptions(key_type="Ed25519", password=None, path="ca")
    expires = datetime.now(tz=tz.utc) + timedelta(days=10)
    ca = CertificateAuthority.objects.init(
        ca_name, key_backend, ca_key_backend_options, subject, expires, key_type="Ed25519", openssh_ca=True
    )

    assert ca.name == ca_name
    assert isinstance(ca.pub.loaded.public_key(), Ed25519PublicKey)
    assert ca.subject == subject

    # verify X509 properties
    assert ca.extensions[ExtensionOID.KEY_USAGE] == key_usage(crl_sign=True, key_cert_sign=True)

    for oid in [
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ExtensionOID.EXTENDED_KEY_USAGE,
        ExtensionOID.TLS_FEATURE,
        ExtensionOID.ISSUER_ALTERNATIVE_NAME,
    ]:
        assert oid not in ca.extensions

    assert ca.is_openssh_ca is True


def test_openssh_ca_for_intermediate(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, root: CertificateAuthority
) -> None:
    """Test creating an intermediate CA for OpenSSH CAs, which is not supported."""
    ca_key_backend_options = StoragesCreatePrivateKeyOptions(key_type="RSA", password=None, path="ca")
    with pytest.raises(ValueError, match="^OpenSSH does not support intermediate authorities$"):
        CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            ca_key_backend_options,
            subject=subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            key_type="Ed25519",
            parent=root,
            use_parent_private_key_options=parent_key_backend_options,
            openssh_ca=True,
        )
    assert CertificateAuthority.objects.filter(name=ca_name).exists() is False


def test_init_with_no_default_hostname(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, usable_child: CertificateAuthority
) -> None:
    """Create an intermediate CA with no default hostname."""
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_child,
            use_parent_private_key_options=parent_key_backend_options,
            default_hostname=False,
        )
    # Without a default hostname, we cannot set sign_* extension fields
    assert ca.sign_authority_information_access is None
    assert ca.sign_certificate_policies is None
    assert ca.sign_crl_distribution_points is None
    assert ca.sign_issuer_alternative_name is None

    # Without a default hostname, we cannot set extensions for the CA itself
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS not in ca.extensions
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in ca.extensions


@pytest.mark.django_db
def test_init_with_extra_extensions(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Test creating a CA with extra extensions."""
    extensions: list[CertificateExtension] = [
        tls_feature(x509.TLSFeatureType.status_request),
        ocsp_no_check(),
        name_constraints(permitted=[dns(".com")]),
        precert_poison(),
        x509.Extension(oid=ExtensionOID.INHIBIT_ANY_POLICY, critical=False, value=x509.InhibitAnyPolicy(3)),
    ]

    expires = datetime.now(tz=tz.utc) + timedelta(days=10)
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name, key_backend, key_backend_options, subject, expires, extensions=extensions
        )
    assert_ca_properties(ca, ca_name)
    assert_certificate(ca, subject)

    expected = [*extensions, basic_constraints(ca=True), key_usage(crl_sign=True, key_cert_sign=True)]
    assert_extensions(ca, expected)


def test_init_with_partial_authority_information_access(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, usable_root: CertificateAuthority
) -> None:
    """Test passing a partial Authority Information Access extension."""
    host = model_settings.CA_DEFAULT_HOSTNAME  # shortcut
    ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": usable_root.serial})
    ocsp_path = reverse("django_ca:ocsp-ca-post", kwargs={"serial": usable_root.serial})

    # Pass no OCSP URIs
    passed_extensions: list[CertificateExtension] = [
        authority_information_access(ca_issuers=[uri("https://example.com/ca-issuer/{CA_ISSUER_PATH}")]),
    ]
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            f"{ca_name}_1",
            key_backend,
            key_backend_options,
            subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_root,
            use_parent_private_key_options=parent_key_backend_options,
            extensions=passed_extensions,
        )

    assert ca.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        ca_issuers=[uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
        ocsp=[uri(f"http://{host}{ocsp_path}")],
    )

    # Pass no CA Issuers
    passed_extensions = [authority_information_access(ocsp=[uri("https://example.com/ocsp/{OCSP_PATH}")])]
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            f"{ca_name}_2",
            key_backend,
            key_backend_options,
            subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_root,
            use_parent_private_key_options=parent_key_backend_options,
            extensions=passed_extensions,
        )
    assert ca.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        ca_issuers=[uri(f"http://{host}{ca_issuer_path}")],
        ocsp=[uri(f"https://example.com/ocsp{ocsp_path}")],
    )


def test_init_with_formatting(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, usable_root: CertificateAuthority
) -> None:
    """Test passing extensions that are formatted."""
    passed_extensions: list[CertificateExtension] = [
        authority_information_access(
            [uri("https://example.com/ca-issuer/{CA_ISSUER_PATH}")],
            [uri("https://example.com/ocsp/{OCSP_PATH}")],
        ),
        crl_distribution_points(distribution_point([uri("http://example.com/crl/{CRL_PATH}")])),
    ]

    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_root,
            use_parent_private_key_options=parent_key_backend_options,
            extensions=passed_extensions,
        )

    extensions = ca.extensions
    ca_issuer_path = reverse("django_ca:issuer", kwargs={"serial": usable_root.serial})
    ocsp_path = reverse("django_ca:ocsp-ca-post", kwargs={"serial": usable_root.serial})
    crl_path = reverse("django_ca:ca-crl", kwargs={"serial": usable_root.serial})

    assert extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == authority_information_access(
        [uri(f"https://example.com/ca-issuer{ca_issuer_path}")],
        [uri(f"https://example.com/ocsp{ocsp_path}")],
    )

    assert extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crl_distribution_points(
        distribution_point([uri(f"http://example.com/crl{crl_path}")])
    )


def test_init_with_formatting_with_no_uri(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, usable_root: CertificateAuthority
) -> None:
    """Test passing extensions with values that cannot be formatted."""
    aia = authority_information_access([dns("ca-issuer.example.com")], [dns("ocsp.example.com")])
    crldp = crl_distribution_points(distribution_point([dns("crl.example.com")]))
    passed_extensions: list[CertificateExtension] = [aia, crldp]

    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_root,
            use_parent_private_key_options=parent_key_backend_options,
            extensions=passed_extensions,
        )

    assert ca.extensions[ExtensionOID.AUTHORITY_INFORMATION_ACCESS] == aia
    assert ca.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crldp


def test_init_with_formatting_with_rdn_in_crldp(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend, usable_root: CertificateAuthority
) -> None:
    """Test passing a relative distinguished name in the CRL Distribution Points extension."""
    crldp = crl_distribution_points(
        distribution_point(relative_name=rdn([(NameOID.COMMON_NAME, "example.com")]))
    )
    passed_extensions: list[CertificateExtension] = [crldp]

    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            datetime.now(tz=tz.utc) + timedelta(days=10),
            parent=usable_root,
            use_parent_private_key_options=parent_key_backend_options,
            extensions=passed_extensions,
        )
    assert_ca_properties(ca, ca_name, parent=usable_root)
    assert_certificate(ca, subject, signer=usable_root)
    assert ca.extensions[ExtensionOID.CRL_DISTRIBUTION_POINTS] == crldp


@pytest.mark.django_db
def test_init_with_no_extensions(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Test passing no extensions."""
    expires = datetime.now(tz=tz.utc) + timedelta(days=10)
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name, key_backend, key_backend_options, subject, expires, extensions=None
        )
    assert_ca_properties(ca, ca_name)
    assert_certificate(ca, subject)
    assert_extensions(ca, [basic_constraints(ca=True), key_usage(crl_sign=True, key_cert_sign=True)])


@pytest.mark.django_db
def test_init_with_acme_parameters(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Test parameters for ACMEv2."""
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            datetime.now(tz=tz.utc) + timedelta(days=10),
            acme_enabled=True,
            acme_profile="client",
            acme_requires_contact=False,
        )
    assert_ca_properties(ca, ca_name, acme_enabled=True, acme_profile="client", acme_requires_contact=False)
    assert_certificate(ca, subject)


@pytest.mark.django_db
def test_init_with_api_parameters(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Test parameters for the REST API."""
    with assert_create_ca_signals():
        ca = CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            datetime.now(tz=tz.utc) + timedelta(days=10),
            api_enabled=True,
        )
    assert_ca_properties(ca, ca_name)
    assert_certificate(ca, subject)


def test_init_with_expires_is_wrong_type(
    ca_name: str, subject: x509.Name, key_backend: StoragesBackend
) -> None:
    """Test init with an expired as None."""
    with pytest.raises(TypeError, match=r"^3: not_after must be a datetime\."):
        CertificateAuthority.objects.init(
            ca_name,
            key_backend,
            key_backend_options,
            subject,
            not_after=3,  # type: ignore[arg-type]  # what we're testing
        )


def test_init_with_naive_expires(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Test init with a naive expired."""
    not_after = datetime(2024, 5, 31)
    with pytest.raises(ValueError, match=r"^not_after must not be a naive datetime\."):
        CertificateAuthority.objects.init(
            ca_name, key_backend, key_backend_options, subject, not_after=not_after
        )


def test_init_with_unknown_profile(ca_name: str, subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Create a CA with a profile that doesn't exist."""
    not_after = datetime.now(tz=tz.utc) + timedelta(days=10)
    with pytest.raises(ValueError, match=r"^foobar: Profile is not defined\.$"):
        CertificateAuthority.objects.init(
            ca_name, key_backend, key_backend_options, subject, not_after, acme_profile="foobar"
        )


@pytest.mark.django_db
def test_init_with_unknown_extension_type(subject: x509.Name, key_backend: StoragesBackend) -> None:
    """Create a CA with an unknown extension throws an error."""
    with pytest.raises(ValueError, match=r"^Cannot add extension of type bool$"):
        CertificateAuthority.objects.init(
            "error",
            key_backend,
            key_backend_options,
            subject,
            not_after=datetime.now(tz=tz.utc) + timedelta(days=10),
            extensions=[True],  # type: ignore[list-item]  # what we are testing
        )
    assert CertificateAuthority.objects.count() == 0


@pytest.mark.django_db
def test_init_with_parent_with_no_use_parent_private_key_options(
    ca_name: str, root: CertificateAuthority, subject: x509.Name, key_backend: StoragesBackend
) -> None:
    """Test that use_parent_private_key_options is a mandatory option when parent is passed."""
    match = r"^use_parent_private_key_options is required when parent is passed\.$"
    expires = datetime.now(tz=tz.utc) + timedelta(days=10)
    with pytest.raises(ValueError, match=match):
        CertificateAuthority.objects.init(
            ca_name, key_backend, key_backend_options, subject, expires, parent=root
        )


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_default(root: CertificateAuthority, child: CertificateAuthority, settings: SettingsWrapper) -> None:
    """Test the correct CA is returned if CA_DEFAULT_CA is set."""
    settings.CA_DEFAULT_CA = CERT_DATA["child"]["serial"]
    assert CertificateAuthority.objects.default() == child
    settings.CA_DEFAULT_CA = CERT_DATA["root"]["serial"]
    assert CertificateAuthority.objects.default() == root


@pytest.mark.usefixtures("child")
def test_default_with_disabled(root: CertificateAuthority, settings: SettingsWrapper) -> None:
    """Test that an exception is raised if the CA is disabled."""
    settings.CA_DEFAULT_CA = CERT_DATA["root"]["serial"]
    root.enabled = False
    root.save()

    with assert_improperly_configured(rf"^CA_DEFAULT_CA: {root.serial} is disabled\.$"):
        CertificateAuthority.objects.default()


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
@pytest.mark.usefixtures("child")
def test_default_with_expired(root: CertificateAuthority, settings: SettingsWrapper) -> None:
    """Test that an exception is raised if CA is expired."""
    settings.CA_DEFAULT_CA = CERT_DATA["root"]["serial"]
    with assert_improperly_configured(rf"^CA_DEFAULT_CA: {root.serial} is expired\.$"):
        CertificateAuthority.objects.default()


@pytest.mark.freeze_time(TIMESTAMPS["before_everything"])
@pytest.mark.usefixtures("child")
def test_default_with_not_yet_valid(root: CertificateAuthority, settings: SettingsWrapper) -> None:
    """Test that an exception is raised if CA is not yet valid."""
    settings.CA_DEFAULT_CA = CERT_DATA["root"]["serial"]
    with assert_improperly_configured(rf"^CA_DEFAULT_CA: {root.serial} is not yet valid\.$"):
        CertificateAuthority.objects.default()


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
@pytest.mark.usefixtures("root", "child", "ed448", "ed25519")
def test_default_with_no_default_ca(settings: SettingsWrapper) -> None:
    """Test what is returned when **no** CA is configured as default."""
    settings.CA_DEFAULT_CA = None
    ca = sorted(CertificateAuthority.objects.all(), key=lambda obj: (obj.not_after, obj.serial))[-1]
    assert CertificateAuthority.objects.default() == ca


@pytest.mark.freeze_time(TIMESTAMPS["everything_expired"])
@pytest.mark.usefixtures("root", "child")
def test_default_with_expired_cas() -> None:
    """Test that exception is raised if no CA is currently valid."""
    with assert_improperly_configured(r"^No CA is currently usable\.$"):
        CertificateAuthority.objects.default()


@pytest.mark.django_db
def test_default_with_unknown_ca_configured(settings: SettingsWrapper) -> None:
    """Test behavior when an unknown CA is manually configured."""
    settings.CA_DEFAULT_CA = "ABC"
    with assert_improperly_configured(r"^CA_DEFAULT_CA: ABC: CA not found\.$"):
        CertificateAuthority.objects.default()


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_create_cert(usable_root: CertificateAuthority, subject: x509.Name) -> None:
    """Test creating the most basic cert possible."""
    csr = CERT_DATA["root-cert"]["csr"]["parsed"]
    profile = profiles[model_settings.CA_DEFAULT_PROFILE]
    with assert_create_cert_signals():
        cert = Certificate.objects.create_cert(usable_root, key_backend_options, csr, subject=subject)
    assert cert.subject == subject
    # TYPEHINT NOTE: default profile always has extensions, so override here
    assert_extensions(cert, list(profile.extensions.values()))  # type: ignore[arg-type]


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_create_cert_cryptography_extensions(usable_root: CertificateAuthority, subject: x509.Name) -> None:
    """Test passing readable extensions."""
    csr = CERT_DATA["root-cert"]["csr"]["parsed"]
    expected_key_usage = key_usage(key_cert_sign=True, key_encipherment=True)
    with assert_create_cert_signals():
        cert = Certificate.objects.create_cert(
            usable_root, key_backend_options, csr, subject=subject, extensions=[expected_key_usage]
        )
    assert cert.subject == subject
    assert_extensions(cert, [expected_key_usage, extended_key_usage(ExtendedKeyUsageOID.SERVER_AUTH)])


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_create_cert_no_cn_or_san(root: CertificateAuthority) -> None:
    """Test that creating a cert with no CommonName or SubjectAlternativeName is an error."""
    csr = CERT_DATA["root-cert"]["csr"]["parsed"]
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "AT")])

    msg = r"^Must name at least a CN or a subjectAlternativeName\.$"
    with pytest.raises(ValueError, match=msg), assert_create_cert_signals(False, False):
        Certificate.objects.create_cert(root, key_backend_options, csr, subject=subject)
    assert Certificate.objects.exists() is False


@pytest.mark.freeze_time(TIMESTAMPS["everything_valid"])
def test_create_cert_with_wrong_profile_type(root: CertificateAuthority, subject: x509.Name) -> None:
    """Test passing a profile with an unsupported type."""
    msg = r"^profile must be of type django_ca\.profiles\.Profile\.$"
    with assert_create_cert_signals(False, False), pytest.raises(TypeError, match=msg):
        Certificate.objects.create_cert(
            root,
            key_backend_options,
            csr=CERT_DATA["root-cert"]["csr"]["parsed"],
            profile=False,  # type: ignore[arg-type] # what we're testing
            subject=subject,
            add_crl_url=False,
            add_ocsp_url=False,
            add_issuer_url=False,
        )
    assert Certificate.objects.exists() is False


class TypingExamples:
    """Test case to create some code that would show an error in type checkers if type hinting is wrong.

    Note that none of these tests are designed to ever be executed.
    """

    # pylint: disable=missing-function-docstring

    def test_get(self) -> CertificateAuthority:
        return CertificateAuthority.objects.get(pk=1)

    def test_first(self) -> CertificateAuthority | None:
        return CertificateAuthority.objects.first()

    def test_get_queryset(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.get_queryset()

    def test_all(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.all()

    def test_filter(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.filter()

    def test_order_by(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.order_by()

    def test_exclude(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.exclude()

    def test_acme(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.acme()

    def test_get_by_serial_or_cn(self) -> CertificateAuthority:
        return CertificateAuthority.objects.get_by_serial_or_cn("foo")

    def test_default(self) -> CertificateAuthority:
        return CertificateAuthority.objects.default()

    def test_disabled(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.disabled()

    def test_enabled(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.enabled()

    def test_invalid(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.invalid()

    def test_usable(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.usable()

    def test_valid(self) -> CertificateAuthorityQuerySet:
        return CertificateAuthority.objects.valid()

    # Tests for Certificate
    def test_cert_get(self) -> Certificate:
        return Certificate.objects.get(pk=1)

    def test_cert_first(self) -> Certificate | None:
        return Certificate.objects.first()

    def test_cert_get_queryset(self) -> CertificateQuerySet:
        return Certificate.objects.get_queryset()

    def test_cert_all(self) -> CertificateQuerySet:
        return Certificate.objects.all()

    def test_cert_filter(self) -> CertificateQuerySet:
        return Certificate.objects.filter()

    def test_cert_order_by(self) -> CertificateQuerySet:
        return Certificate.objects.order_by()

    def test_cert_revoked(self) -> CertificateQuerySet:
        return Certificate.objects.revoked()

    def test_cert_expired(self) -> CertificateQuerySet:
        return Certificate.objects.expired()

    def test_cert_not_yet_valid(self) -> CertificateQuerySet:
        return Certificate.objects.not_yet_valid()

    def test_cert_valid(self) -> CertificateQuerySet:
        return Certificate.objects.valid()
