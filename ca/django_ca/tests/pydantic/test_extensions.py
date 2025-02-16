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

"""Test Pydantic models for extensions."""

import re
from typing import Any, get_args

from pydantic import ValidationError

from cryptography import x509
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    CertificatePoliciesOID,
    ExtendedKeyUsageOID,
    NameOID,
    SubjectInformationAccessOID,
)

import pytest

from django_ca import constants
from django_ca.constants import ExtensionOID
from django_ca.pydantic.extension_attributes import (
    AccessDescriptionModel,
    AdmissionModel,
    BasicConstraintsValueModel,
    DistributionPointModel,
    IssuingDistributionPointValueModel,
    NamingAuthorityModel,
    ProfessionInfoModel,
    SignedCertificateTimestampModel,
    UnrecognizedExtensionValueModel,
)
from django_ca.pydantic.extensions import (
    EXTENSION_MODEL_OIDS,
    AdmissionsModel,
    AlternativeNameBaseModel,
    AuthorityInformationAccessModel,
    AuthorityKeyIdentifierModel,
    BasicConstraintsModel,
    CertificateExtensionModel,
    CertificateExtensionModelList,
    CertificatePoliciesModel,
    ConfigurableExtensionModel,
    CRLDistributionPointsModel,
    CRLNumberModel,
    DeltaCRLIndicatorModel,
    ExtendedKeyUsageModel,
    ExtensionModel,
    ExtensionModelTypeVar,
    FreshestCRLModel,
    InhibitAnyPolicyModel,
    IssuerAlternativeNameModel,
    IssuingDistributionPointModel,
    KeyUsageModel,
    MSCertificateTemplateModel,
    NameConstraintsModel,
    OCSPNoCheckModel,
    PolicyConstraintsModel,
    PrecertificateSignedCertificateTimestampsModel,
    PrecertPoisonModel,
    SignedCertificateTimestampsModel,
    SubjectAlternativeNameModel,
    SubjectInformationAccessModel,
    SubjectKeyIdentifierModel,
    TLSFeatureModel,
    UnrecognizedExtensionModel,
)
from django_ca.tests.base.constants import CERT_DATA
from django_ca.tests.base.doctest import doctest_module
from django_ca.tests.base.utils import dns, key_usage, uri
from django_ca.tests.pydantic.base import (
    ExpectedErrors,
    assert_cryptography_model,
    assert_validation_errors,
)
from django_ca.typehints import AlternativeNameExtensionType, AlternativeNameTypeVar

DISTRIBUTION_POINT_REASONS_ERROR = (
    "Input should be 'aa_compromise', 'affiliation_changed', 'ca_compromise', 'certificate_hold', "
    "'cessation_of_operation', 'key_compromise', 'privilege_withdrawn' or 'superseded'"
)

KNOWN_EXTENSION_OIDS = list(
    filter(
        lambda attr: isinstance(attr, x509.ObjectIdentifier)
        and attr
        not in (
            ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES,  # cryptography has OID, but no class
            ExtensionOID.POLICY_MAPPINGS,  # cryptography has OID, but no class
        ),
        [getattr(ExtensionOID, attr) for attr in dir(ExtensionOID)],
    )
)

NAME = {"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}
GENERAL_NAME = {"type": "DNS", "value": "example.com"}

MUST_BE_CRITICAL_ERROR = (
    "value_error",
    ("critical",),
    "Value error, this extension must be marked as critical",
)
MUST_BE_NON_CRITICAL_ERROR = (
    "value_error",
    ("critical",),
    "Value error, this extension must be marked as non-critical",
)


def assert_extension_model(
    model_class: type[ExtensionModelTypeVar],
    parameters: Any,
    expected: x509.ExtensionType,
    critical: bool | None,
) -> ExtensionModelTypeVar:
    """Test the given extension model."""
    kwargs = {"value": parameters}
    if critical is None:
        expected_critical = critical = constants.EXTENSION_DEFAULT_CRITICAL[expected.oid]
    else:
        expected_critical = kwargs["critical"] = critical

    extension = x509.Extension(critical=critical, oid=expected.oid, value=expected)
    model = assert_cryptography_model(model_class, kwargs, extension)

    assert model.critical == expected_critical
    assert model.type == constants.EXTENSION_KEYS.get(expected.oid, "unknown")
    if hasattr(model, "_extension_type"):
        assert model._extension_type is type(expected)  # pylint: disable=protected-access

    return model


def test_doctests() -> None:
    """Load doctests."""
    failures, *_tests = doctest_module("django_ca.pydantic.extensions")
    assert failures == 0, f"{failures} doctests failed, see above for output."


def test_doctest_extension_attributes() -> None:
    """Load doctests."""
    failures, *_tests = doctest_module("django_ca.pydantic.extension_attributes")
    assert failures == 0, f"{failures} doctests failed, see above for output."


def test_critical_validation() -> None:
    """Test critical validation with PrecertPoison as an example.

    This test also checks the `validate_required_critical` validation context.
    """
    assert_extension_model(PrecertPoisonModel, None, x509.PrecertPoison(), True)

    # When manually passing critical=False, we get a validation error
    assert_validation_errors(
        PrecertPoisonModel,
        {"critical": False},
        [("value_error", ("critical",), "Value error, this extension must be marked as critical")],
    )

    # This extension violates RFC 5280 spec, but of course could appear in a certificate
    ext = x509.Extension(oid=ExtensionOID.PRECERT_POISON, critical=False, value=x509.PrecertPoison())

    # Without validation context, validating the extension fails with an error
    with pytest.raises(ValidationError) as ex_info:
        PrecertPoisonModel.model_validate(ext)
    errors = ex_info.value.errors()
    assert len(errors) == 1, errors
    assert errors[0]["type"] == "value_error"
    assert errors[0]["loc"] == ("critical",)
    assert errors[0]["msg"] == "Value error, this extension must be marked as critical"

    # Finally, if we pass validate_required_critical=False, we can instantiate this model
    model = PrecertPoisonModel.model_validate(ext, context={"validate_required_critical": False})
    assert model.critical is False


@pytest.mark.parametrize(
    ("parameters", "expected"),
    (
        ({}, x509.NamingAuthority(id=None, url=None, text=None)),
        (
            {"id": "1.2.3", "url": "https://example.com", "text": "example"},
            x509.NamingAuthority(
                id=x509.ObjectIdentifier("1.2.3"), url="https://example.com", text="example"
            ),
        ),
    ),
)
def test_naming_authority_model(parameters: dict[str, Any], expected: x509.NamingAuthority) -> None:
    """Test the NamingAuthorityModel."""
    assert_cryptography_model(NamingAuthorityModel, parameters, expected)


@pytest.mark.parametrize(
    ("parameters", "expected"),
    (
        (
            {"profession_items": ["example_profession_items"]},
            x509.ProfessionInfo(
                naming_authority=None,
                profession_items=["example_profession_items"],
                profession_oids=None,
                registration_number=None,
                add_profession_info=None,
            ),
        ),
        (
            {
                "naming_authority": {},
                "profession_items": ["example_profession_items"],
                "profession_oids": ["1.2.3"],
                "registration_number": "example_registration_number",
                "add_profession_info": b"example_add_profession_info",
            },
            x509.ProfessionInfo(
                naming_authority=x509.NamingAuthority(id=None, url=None, text=None),
                profession_items=["example_profession_items"],
                profession_oids=[x509.ObjectIdentifier("1.2.3")],
                registration_number="example_registration_number",
                add_profession_info=b"example_add_profession_info",
            ),
        ),
    ),
)
def test_profession_info_model(parameters: dict[str, Any], expected: x509.ProfessionInfo) -> None:
    """Test the ProfessionInfoModel."""
    assert_cryptography_model(ProfessionInfoModel, parameters, expected)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            {
                "naming_authority": {},
                "profession_items": ["example_profession_items"],
                "profession_oids": ["1.2.3", "1.2.4"],
                "registration_number": "example_registration_number",
                "add_profession_info": b"example_add_profession_info",
            },
            [
                (
                    "value_error",
                    (),
                    "Value error, if present, profession_oids must have the same length as profession_items.",
                )
            ],
        ),
    ),
)
def test_profession_info_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the ProfessionInfoModel."""
    assert_validation_errors(ProfessionInfoModel, parameters, expected_errors)


@pytest.mark.parametrize(
    ("parameters", "expected"),
    (
        (
            {"profession_infos": [{"profession_items": ["example_profession_items"]}]},
            x509.Admission(
                admission_authority=None,
                naming_authority=None,
                profession_infos=[
                    x509.ProfessionInfo(
                        naming_authority=None,
                        profession_items=["example_profession_items"],
                        profession_oids=None,
                        registration_number=None,
                        add_profession_info=None,
                    )
                ],
            ),
        ),
        (
            {
                "admission_authority": {"type": "URI", "value": "https://example.com"},
                "naming_authority": {},
                "profession_infos": [
                    {"profession_items": ["example_profession_items"]},
                    {
                        "naming_authority": {},
                        "profession_items": ["example_profession_items"],
                        "profession_oids": ["1.2.3"],
                        "registration_number": "example_registration_number",
                        "add_profession_info": b"example_add_profession_info",
                    },
                ],
            },
            x509.Admission(
                admission_authority=uri("https://example.com"),
                naming_authority=x509.NamingAuthority(id=None, url=None, text=None),
                profession_infos=[
                    x509.ProfessionInfo(
                        naming_authority=None,
                        profession_items=["example_profession_items"],
                        profession_oids=None,
                        registration_number=None,
                        add_profession_info=None,
                    ),
                    x509.ProfessionInfo(
                        naming_authority=x509.NamingAuthority(id=None, url=None, text=None),
                        profession_items=["example_profession_items"],
                        profession_oids=[x509.ObjectIdentifier("1.2.3")],
                        registration_number="example_registration_number",
                        add_profession_info=b"example_add_profession_info",
                    ),
                ],
            ),
        ),
    ),
)
def test_admission_model(parameters: dict[str, Any], expected: x509.Admission) -> None:
    """Test the AdmissionModel."""
    assert_cryptography_model(AdmissionModel, parameters, expected)


@pytest.mark.parametrize("critical", (False, True, None))
@pytest.mark.parametrize(
    ("parameters", "admissions"),
    (
        ({}, x509.Admissions(authority=None, admissions=[])),
        (
            {"authority": {"type": "URI", "value": "https://example.com"}, "admissions": []},
            x509.Admissions(authority=uri("https://example.com"), admissions=[]),
        ),
        (
            {
                "authority": {"type": "URI", "value": "https://example.com"},
                "admissions": [
                    {"profession_infos": [{"profession_items": ["example_profession_items"]}]},
                ],
            },
            x509.Admissions(
                authority=uri("https://example.com"),
                admissions=[
                    x509.Admission(
                        admission_authority=None,
                        naming_authority=None,
                        profession_infos=[
                            x509.ProfessionInfo(
                                naming_authority=None,
                                profession_items=["example_profession_items"],
                                profession_oids=None,
                                registration_number=None,
                                add_profession_info=None,
                            )
                        ],
                    )
                ],
            ),
        ),
    ),
)
def test_admissions(
    critical: bool | None, parameters: dict[str, Any], admissions: x509.Admissions
) -> None:
    """Test the Admissions extension."""
    assert_extension_model(AdmissionsModel, parameters, admissions, critical)


@pytest.mark.parametrize(
    ("parameters", "expected"),
    (
        (
            {
                "access_method": AuthorityInformationAccessOID.OCSP.dotted_string,
                "access_location": GENERAL_NAME,
            },
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP, dns("example.com")),
        ),
        (
            {"access_method": "ocsp", "access_location": GENERAL_NAME},
            x509.AccessDescription(AuthorityInformationAccessOID.OCSP, dns("example.com")),
        ),
        (
            {"access_method": "ca_issuers", "access_location": GENERAL_NAME},
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, dns("example.com")),
        ),
        (
            {"access_method": "ca_repository", "access_location": GENERAL_NAME},
            x509.AccessDescription(SubjectInformationAccessOID.CA_REPOSITORY, dns("example.com")),
        ),
    ),
)
def test_access_description_model(parameters: dict[str, Any], expected: x509.AccessDescription) -> None:
    """Test the AccessDescriptionModel."""
    assert_cryptography_model(AccessDescriptionModel, parameters, expected)


@pytest.mark.parametrize(
    ("parameters", "expected"),
    (
        (
            {"full_name": [GENERAL_NAME]},
            x509.DistributionPoint(
                full_name=[dns("example.com")], relative_name=None, crl_issuer=None, reasons=None
            ),
        ),
        (
            {"relative_name": [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}]},
            x509.DistributionPoint(
                full_name=None,
                relative_name=x509.RelativeDistinguishedName(
                    [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")]
                ),
                crl_issuer=None,
                reasons=None,
            ),
        ),
        (
            {
                "full_name": [GENERAL_NAME],
                "crl_issuer": [{"type": "DNS", "value": "example.net"}],
                "reasons": ["key_compromise", "superseded"],
            },
            x509.DistributionPoint(
                full_name=[dns("example.com")],
                relative_name=None,
                crl_issuer=[dns("example.net")],
                reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.superseded]),
            ),
        ),
    ),
)
def test_distribution_point(parameters: dict[str, Any], expected: x509.DistributionPoint) -> None:
    """Test the DistributionPointModel."""
    assert_cryptography_model(DistributionPointModel, parameters, expected)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            {
                "full_name": [GENERAL_NAME],
                "relative_name": [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}],
            },
            [("value_error", (), "Value error, must give exactly one of full_name or relative_name.")],
        ),
        (
            {},
            [
                (
                    "value_error",
                    (),
                    "Value error, either full_name, relative_name or crl_issuer must be provided.",
                )
            ],
        ),
    ),
)
def test_distribution_point_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the DistributionPointModel."""
    assert_validation_errors(DistributionPointModel, parameters, expected_errors)


@pytest.mark.parametrize(
    ("parameters", "expected"),
    (
        (
            {"full_name": [GENERAL_NAME]},
            x509.IssuingDistributionPoint(
                full_name=[dns("example.com")],
                relative_name=None,
                only_some_reasons=None,
                only_contains_attribute_certs=False,
                indirect_crl=False,
                only_contains_ca_certs=False,
                only_contains_user_certs=False,
            ),
        ),
        (
            {"relative_name": [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}]},
            x509.IssuingDistributionPoint(
                full_name=None,
                relative_name=x509.RelativeDistinguishedName(
                    [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")]
                ),
                only_some_reasons=None,
                only_contains_attribute_certs=False,
                indirect_crl=False,
                only_contains_ca_certs=False,
                only_contains_user_certs=False,
            ),
        ),
        (
            {
                "full_name": [GENERAL_NAME],
                "only_contains_ca_certs": True,
                "only_some_reasons": ["key_compromise", "superseded"],
            },
            x509.IssuingDistributionPoint(
                full_name=[dns("example.com")],
                relative_name=None,
                only_some_reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.superseded]),
                only_contains_attribute_certs=False,
                indirect_crl=False,
                only_contains_ca_certs=True,
                only_contains_user_certs=False,
            ),
        ),
    ),
)
def test_issuing_distribution_point_value(
    parameters: dict[str, Any], expected: x509.IssuingDistributionPoint
) -> None:
    """Test the DistributionPointModel."""
    assert_cryptography_model(IssuingDistributionPointValueModel, parameters, expected)


def test_signed_certificate_timestamp(signed_certificate_timestamp_pub: x509.Certificate) -> None:
    """Test the SignedCertificateTimestampModel.

    .. NOTE:: This tests the nested class, not the extension.
    """
    try:
        precertificate_signed_certificate_timestamps = (
            signed_certificate_timestamp_pub.extensions.get_extension_for_class(
                x509.PrecertificateSignedCertificateTimestamps
            )
        )
        for sct in precertificate_signed_certificate_timestamps.value:
            SignedCertificateTimestampModel.model_validate(sct)
    except x509.ExtensionNotFound:
        pass

    try:
        signed_certificate_timestamps = signed_certificate_timestamp_pub.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
        for sct in signed_certificate_timestamps.value:
            SignedCertificateTimestampModel.model_validate(sct)
    except x509.ExtensionNotFound:
        pass


@pytest.mark.parametrize("critical", (True, False, None))
@pytest.mark.parametrize(("general_names", "parsed_general_names"), (([GENERAL_NAME], [dns("example.com")]),))
@pytest.mark.parametrize(
    ("model", "extension_type"),
    (
        (SubjectAlternativeNameModel, x509.SubjectAlternativeName),
        (IssuerAlternativeNameModel, x509.IssuerAlternativeName),
    ),
)
def test_alternative_name_extensions(
    critical: bool | None,
    general_names: list[dict[str, str]],
    parsed_general_names: list[x509.GeneralName],
    model: AlternativeNameBaseModel[AlternativeNameTypeVar],
    extension_type: type[AlternativeNameExtensionType],
) -> None:
    """Test the AlternativeName extensions."""
    extension = extension_type(general_names=parsed_general_names)
    assert_extension_model(model, general_names, extension, critical)  # type: ignore[arg-type]


@pytest.mark.parametrize("model", (SubjectAlternativeNameModel, IssuerAlternativeNameModel))
@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        ([], [("value_error", ("value",), "Value error, value must not be empty")]),
        ([GENERAL_NAME] * 2, [("value_error", ("value",), re.compile("value must be unique$"))]),
    ),
)
def test_alternative_name_extensions_errors(
    model: type[SubjectAlternativeNameModel] | type[IssuerAlternativeNameModel],
    parameters: dict[str, Any],
    expected_errors: ExpectedErrors,
) -> None:
    """Test validation errors SubjectAlternativeNameModel and IssuerAlternativeNameModel."""
    assert_validation_errors(model, {"value": parameters}, expected_errors)


@pytest.mark.parametrize("critical", (False, None))
@pytest.mark.parametrize(
    ("parameters", "descriptions"),
    (
        (
            [{"access_method": "ocsp", "access_location": GENERAL_NAME}],
            [x509.AccessDescription(AuthorityInformationAccessOID.OCSP, dns("example.com"))],
        ),
        (
            [
                {"access_method": "ocsp", "access_location": GENERAL_NAME},
                {"access_method": "ca_issuers", "access_location": {"type": "DNS", "value": "example.net"}},
            ],
            [
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, dns("example.com")),
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, dns("example.net")),
            ],
        ),
    ),
)
def test_authority_information_access(
    critical: bool | None, parameters: dict[str, Any], descriptions: list[x509.AccessDescription]
) -> None:
    """Test the Information Access extensions."""
    extension = x509.AuthorityInformationAccess(descriptions)
    assert_extension_model(AuthorityInformationAccessModel, parameters, extension, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        ({"value": []}, [("value_error", ("value",), "Value error, value must not be empty")]),
        (
            {"value": [{"access_method": "ocsp", "access_location": GENERAL_NAME}] * 2},
            [("value_error", ("value",), re.compile("value must be unique$"))],
        ),
        (
            {
                "value": [{"access_method": "ocsp", "access_location": GENERAL_NAME}],
                "critical": True,
            },
            [MUST_BE_NON_CRITICAL_ERROR],
        ),
        (
            {"value": [{"access_method": "ca_repository", "access_location": GENERAL_NAME}]},
            [
                (
                    "value_error",
                    (),
                    f"Value error, {SubjectInformationAccessOID.CA_REPOSITORY.dotted_string}: access_method "
                    "not acceptable for this extension.",
                )
            ],
        ),
    ),
)
def test_authority_information_access_errors(
    parameters: dict[str, Any], expected_errors: ExpectedErrors
) -> None:
    """Test validation errors for the AuthorityInformationAccessModel."""
    assert_validation_errors(AuthorityInformationAccessModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (False, None))
@pytest.mark.parametrize(
    ("parameters", "extension"),
    (
        (
            {"key_identifier": b"MTIz"},
            x509.AuthorityKeyIdentifier(
                key_identifier=b"123", authority_cert_issuer=None, authority_cert_serial_number=None
            ),
        ),
        (
            {
                "key_identifier": b"AHgwMA==",
                "authority_cert_issuer": [GENERAL_NAME],
                "authority_cert_serial_number": 123,
            },
            x509.AuthorityKeyIdentifier(
                key_identifier=b"\0x00",
                authority_cert_issuer=[dns("example.com")],
                authority_cert_serial_number=123,
            ),
        ),
        (
            {
                "key_identifier": None,
                "authority_cert_issuer": [GENERAL_NAME],
                "authority_cert_serial_number": 123,
            },
            x509.AuthorityKeyIdentifier(
                key_identifier=None,
                authority_cert_issuer=[dns("example.com")],
                authority_cert_serial_number=123,
            ),
        ),
    ),
)
def test_authority_key_identifier(
    critical: bool | None, parameters: dict[str, Any], extension: x509.AuthorityKeyIdentifier
) -> None:
    """Test the AuthorityKeyIdentifierModel."""
    assert_extension_model(AuthorityKeyIdentifierModel, parameters, extension, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            {
                "value": {
                    "key_identifier": None,
                    "authority_cert_issuer": [GENERAL_NAME],
                    "authority_cert_serial_number": None,
                }
            },
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, authority_cert_issuer and authority_cert_serial_number must both be "
                    "present or both None",
                )
            ],
        ),
        ({"value": {"key_identifier": b"AHgwMA=="}, "critical": True}, [MUST_BE_NON_CRITICAL_ERROR]),
        (
            {
                "value": {
                    "key_identifier": None,
                    "authority_cert_issuer": None,
                    "authority_cert_serial_number": 123,
                }
            },
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, authority_cert_issuer and authority_cert_serial_number must both be "
                    "present or both None",
                )
            ],
        ),
        (
            {
                "value": {
                    "key_identifier": None,
                    "authority_cert_issuer": None,
                    "authority_cert_serial_number": None,
                }
            },
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, At least one of key_identifier or "
                    "authority_cert_issuer/authority_cert_serial_number must be given.",
                )
            ],
        ),
    ),
)
def test_authority_key_identifier_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the AuthorityKeyIdentifierModel."""
    assert_validation_errors(AuthorityKeyIdentifierModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (True, False, None))
@pytest.mark.parametrize(
    ("parameters", "extension"),
    (
        ({"ca": False, "path_length": None}, x509.BasicConstraints(ca=False, path_length=None)),
        ({"ca": True, "path_length": None}, x509.BasicConstraints(ca=True, path_length=None)),
        ({"ca": True, "path_length": 0}, x509.BasicConstraints(ca=True, path_length=0)),
        ({"ca": True, "path_length": 1}, x509.BasicConstraints(ca=True, path_length=1)),
    ),
)
def test_basic_constraints(
    critical: bool | None, parameters: dict[str, Any], extension: x509.BasicConstraints
) -> None:
    """Test the BasicConstraintsModel."""
    model = assert_extension_model(BasicConstraintsModel, parameters, extension, critical)
    assert model.model_dump(mode="json") == {
        "critical": True if critical is None else critical,  # default is True
        "type": "basic_constraints",
        "value": parameters,
    }


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            {},
            # type, loc, msg as tuple
            [
                ("missing", ("value", "ca"), "Field required"),
                ("missing", ("value", "path_length"), "Field required"),
            ],
        ),
        (
            {"ca": False, "path_length": 0},
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, path_length must be None when ca is False",
                )
            ],
        ),
        (
            {"ca": True, "path_length": -1},
            [("greater_than_equal", ("value", "path_length"), "Input should be greater than or equal to 0")],
        ),
    ),
)
def test_basic_constraints_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the BasicConstraintsModel."""
    assert_validation_errors(BasicConstraintsModel, {"value": parameters}, expected_errors)


@pytest.mark.parametrize("critical", (True, False, None))
@pytest.mark.parametrize(
    ("parameters", "policies"),
    (
        (
            (
                [
                    {
                        "policy_identifier": CertificatePoliciesOID.ANY_POLICY.dotted_string,
                        "policy_qualifiers": None,
                    }
                ]
            ),
            [
                x509.PolicyInformation(
                    policy_identifier=CertificatePoliciesOID.ANY_POLICY, policy_qualifiers=None
                )
            ],
        ),
        (
            (
                [
                    {
                        "policy_identifier": CertificatePoliciesOID.ANY_POLICY.dotted_string,
                        "policy_qualifiers": ["CPS"],
                    }
                ]
            ),
            [
                x509.PolicyInformation(
                    policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                    policy_qualifiers=["CPS"],
                )
            ],
        ),
        (
            (
                [
                    {
                        "policy_identifier": CertificatePoliciesOID.ANY_POLICY.dotted_string,
                        "policy_qualifiers": [
                            "CPS",
                            {"explicit_text": "explicit text", "notice_reference": None},
                        ],
                    }
                ]
            ),
            [
                x509.PolicyInformation(
                    policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                    policy_qualifiers=[
                        "CPS",
                        x509.UserNotice(notice_reference=None, explicit_text="explicit text"),
                    ],
                )
            ],
        ),
        (
            (
                [
                    {
                        "policy_identifier": CertificatePoliciesOID.ANY_POLICY.dotted_string,
                        "policy_qualifiers": [
                            "CPS",
                            {
                                "explicit_text": "explicit text",
                                "notice_reference": {"organization": None, "notice_numbers": [1, 2, 3]},
                            },
                        ],
                    }
                ]
            ),
            [
                x509.PolicyInformation(
                    policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                    policy_qualifiers=[
                        "CPS",
                        x509.UserNotice(
                            notice_reference=x509.NoticeReference(
                                organization=None, notice_numbers=[1, 2, 3]
                            ),
                            explicit_text="explicit text",
                        ),
                    ],
                )
            ],
        ),
        (
            (
                [
                    {
                        "policy_identifier": CertificatePoliciesOID.ANY_POLICY.dotted_string,
                        "policy_qualifiers": [
                            "CPS",
                            {
                                "explicit_text": "explicit text",
                                "notice_reference": {"organization": "org", "notice_numbers": [1, 2, 3]},
                            },
                        ],
                    }
                ]
            ),
            [
                x509.PolicyInformation(
                    policy_identifier=CertificatePoliciesOID.ANY_POLICY,
                    policy_qualifiers=[
                        "CPS",
                        x509.UserNotice(
                            notice_reference=x509.NoticeReference(
                                organization="org", notice_numbers=[1, 2, 3]
                            ),
                            explicit_text="explicit text",
                        ),
                    ],
                )
            ],
        ),
    ),
)
def test_certificate_policies(
    critical: bool | None, parameters: list[dict[str, Any]], policies: list[x509.PolicyInformation]
) -> None:
    """Test the CertificatePoliciesModel."""
    assert_extension_model(CertificatePoliciesModel, parameters, x509.CertificatePolicies(policies), critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            [],
            [("value_error", ("value",), "Value error, value must not be empty")],
        ),
        (
            [
                {
                    "policy_identifier": CertificatePoliciesOID.ANY_POLICY.dotted_string,
                    "policy_qualifiers": None,
                }
            ]
            * 2,
            [
                (
                    "value_error",
                    ("value",),
                    re.compile(r"Value error, .*: value must be unique"),
                )
            ],
        ),
    ),
)
def test_certificate_policies_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for CRLDistributionPointsModel and FreshestCRLModel."""
    assert_validation_errors(CertificatePoliciesModel, {"value": parameters}, expected_errors)


DISTRIBUTION_POINTS_PARAMETERS = (
    (
        [{"full_name": [GENERAL_NAME]}],
        [
            x509.DistributionPoint(
                full_name=[dns("example.com")], relative_name=None, crl_issuer=None, reasons=None
            )
        ],
    ),
    (
        [
            {
                "relative_name": [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}],
                "crl_issuer": [{"type": "DNS", "value": "example.net"}],
                "reasons": ["key_compromise", "superseded"],
            },
        ],
        [
            x509.DistributionPoint(
                full_name=None,
                relative_name=x509.RelativeDistinguishedName(
                    [x509.NameAttribute(oid=NameOID.COMMON_NAME, value="example.com")]
                ),
                crl_issuer=[dns("example.net")],
                reasons=frozenset([x509.ReasonFlags.key_compromise, x509.ReasonFlags.superseded]),
            )
        ],
    ),
)


@pytest.mark.parametrize("critical", (True, False, None))
@pytest.mark.parametrize(
    ("parameters", "distribution_points"),
    DISTRIBUTION_POINTS_PARAMETERS,
)
def test_crl_distribution_points(
    critical: bool | None,
    parameters: list[dict[str, Any]],
    distribution_points: list[x509.DistributionPoint],
) -> None:
    """Test the CRLDistributionPointsModel."""
    assert_extension_model(
        CRLDistributionPointsModel, parameters, x509.CRLDistributionPoints(distribution_points), critical
    )


@pytest.mark.parametrize("model", (CRLDistributionPointsModel, FreshestCRLModel))
@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            [],
            [("value_error", ("value",), "Value error, value must not be empty")],
        ),
        (
            [{"full_name": [GENERAL_NAME]}] * 2,
            [
                (
                    "value_error",
                    ("value",),
                    re.compile(r"Value error, .*: value must be unique"),
                )
            ],
        ),
    ),
)
def test_distribution_point_extension_errors(
    model: type[FreshestCRLModel] | type[CRLDistributionPointsModel],
    parameters: dict[str, Any],
    expected_errors: ExpectedErrors,
) -> None:
    """Test common validation errors for CRLDistributionPointsModel and FreshestCRLModel."""
    assert_validation_errors(model, {"value": parameters}, expected_errors)


@pytest.mark.parametrize("critical", (False, None))
@pytest.mark.parametrize("crl_number", (0, 1))
def test_crl_number(critical: bool | None, crl_number: int) -> None:
    """Test the CRLNumberModel."""
    assert_extension_model(CRLNumberModel, crl_number, x509.CRLNumber(crl_number), critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        ({"value": -1}, [("greater_than_equal", ("value",), "Input should be greater than or equal to 0")]),
        ({"value": 0, "critical": True}, [MUST_BE_NON_CRITICAL_ERROR]),
    ),
)
def test_crl_number_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the CRLNumberModel."""
    assert_validation_errors(CRLNumberModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (True, None))
@pytest.mark.parametrize("crl_number", (0, 1, 2))
def test_delta_crl_indicator(critical: bool | None, crl_number: int) -> None:
    """Test the DeltaCRLModel."""
    assert_extension_model(DeltaCRLIndicatorModel, crl_number, x509.DeltaCRLIndicator(crl_number), critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        ({"value": -1}, [("greater_than_equal", ("value",), "Input should be greater than or equal to 0")]),
        ({"value": 0, "critical": False}, [MUST_BE_CRITICAL_ERROR]),
    ),
)
def test_delta_crl_indicator_errors(
    parameters: dict[str, Any],
    expected_errors: ExpectedErrors,
) -> None:
    """Test validation errors for the DeltaCRLIndicatorModel."""
    assert_validation_errors(DeltaCRLIndicatorModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (True, False, None))
@pytest.mark.parametrize(
    ("usages", "extension"),
    (
        (
            [ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string, ExtendedKeyUsageOID.SERVER_AUTH.dotted_string],
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
        ),
        (
            ["clientAuth", "serverAuth"],
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
        ),
        (["1.2.3"], x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.2.3")])),
    ),
)
def test_extended_key_usage(
    critical: bool | None,
    usages: list[str | x509.ObjectIdentifier],
    extension: x509.ExtendedKeyUsage,
) -> None:
    """Test the ExtendedKeyUsageModel."""
    assert_extension_model(ExtendedKeyUsageModel, usages, extension, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            [],
            [("value_error", ("value",), "Value error, value must not be empty")],
        ),
        (
            ["clientAuth", "clientAuth"],
            [
                (
                    "value_error",
                    ("value",),
                    f"Value error, {ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string}: value must be unique",
                )
            ],
        ),
        (
            ["clientAuth", ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string],
            [
                (
                    "value_error",
                    ("value",),
                    f"Value error, {ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string}: value must be unique",
                )
            ],
        ),
        (
            ["foobar"],
            [("value_error", ("value", 0), "Value error, foobar: Invalid object identifier")],
        ),
    ),
)
def test_extended_key_usage_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the ExtendedKeyUsageModel."""
    assert_validation_errors(ExtendedKeyUsageModel, {"value": parameters}, expected_errors)


@pytest.mark.parametrize("critical", (False, None))
@pytest.mark.parametrize(("parameters", "distribution_points"), DISTRIBUTION_POINTS_PARAMETERS)
def test_freshest_crl(
    critical: bool | None,
    parameters: list[dict[str, Any]],
    distribution_points: list[x509.DistributionPoint],
) -> None:
    """Test the CRLDistributionPointsModel."""
    assert_extension_model(FreshestCRLModel, parameters, x509.FreshestCRL(distribution_points), critical)


def test_freshest_crl_critical_error() -> None:
    """Test critical validation errors for the FreshestCRLModel.

    NOTE: other errors are validated together with CRLDistributionPointsModel.
    """
    assert_validation_errors(
        FreshestCRLModel,
        {"value": [{"full_name": [GENERAL_NAME]}], "critical": True},
        [MUST_BE_NON_CRITICAL_ERROR],
    )


@pytest.mark.parametrize("critical", (True, None))
@pytest.mark.parametrize("skip_certs", (0, 1))
def test_inhibit_any_policy(critical: bool | None, skip_certs: int) -> None:
    """Test the InhibitAnyPolicyModel."""
    assert_extension_model(InhibitAnyPolicyModel, skip_certs, x509.InhibitAnyPolicy(skip_certs), critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        ({"value": -1}, [("greater_than_equal", ("value",), "Input should be greater than or equal to 0")]),
        ({"value": 0, "critical": False}, [MUST_BE_CRITICAL_ERROR]),
    ),
)
def test_inhibit_any_policy_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the InhibitAnyPolicyModel."""
    assert_validation_errors(InhibitAnyPolicyModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (True, None))
@pytest.mark.parametrize(
    ("parameters", "issuing_distribution_point"),
    (
        (
            {"full_name": [GENERAL_NAME]},
            x509.IssuingDistributionPoint(
                full_name=[dns("example.com")],
                relative_name=None,
                only_some_reasons=None,
                only_contains_attribute_certs=False,
                indirect_crl=False,
                only_contains_ca_certs=False,
                only_contains_user_certs=False,
            ),
        ),
    ),
)
def test_issuing_distribution_point(
    critical: bool | None,
    parameters: dict[str, Any],
    issuing_distribution_point: x509.IssuingDistributionPoint,
) -> None:
    """Test the IssuingDistributionPointModel."""
    assert_extension_model(IssuingDistributionPointModel, parameters, issuing_distribution_point, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        ({"value": {}}, [("value_error", ("value",), "Value error, cannot create empty extension")]),
        (
            {"value": {"full_name": [GENERAL_NAME], "relative_name": [NAME]}},
            [("value_error", ("value",), "Value error, only one of full_name or relative_name may be True")],
        ),
        (  # unspecified is not a valid reason in this extension
            {"value": {"full_name": [GENERAL_NAME], "only_some_reasons": ["unspecified", "remove_from_crl"]}},
            [
                ("literal_error", ("value", "only_some_reasons", 0), DISTRIBUTION_POINT_REASONS_ERROR),
                ("literal_error", ("value", "only_some_reasons", 1), DISTRIBUTION_POINT_REASONS_ERROR),
            ],
        ),
        (
            {"value": {"only_contains_user_certs": True, "only_contains_ca_certs": True}},
            [
                (
                    "value_error",
                    ("value",),
                    re.compile("Value error, only one can be set: only_contains_user_certs,*"),
                ),
            ],
        ),
        (
            {"value": {"indirect_crl": True, "only_contains_attribute_certs": True}},
            [
                (
                    "value_error",
                    ("value",),
                    re.compile("Value error, only one can be set: only_contains_user_certs,*"),
                ),
            ],
        ),
    ),
)
def test_issuing_distribution_point_errors(
    parameters: dict[str, Any], expected_errors: ExpectedErrors
) -> None:
    """Test errors for the IssuingDistributionPointModel model."""
    assert_validation_errors(IssuingDistributionPointModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (True, False, None))
@pytest.mark.parametrize(
    ("parameters", "extension"),
    (
        (["crl_sign"], key_usage(crl_sign=True).value),
        (
            ["crl_sign", "key_cert_sign", "content_commitment"],
            key_usage(crl_sign=True, key_cert_sign=True, content_commitment=True).value,
        ),
    ),
)
def test_key_usage(critical: bool | None, parameters: dict[str, bool], extension: x509.KeyUsage) -> None:
    """Test the KeyUsageModel."""
    assert_extension_model(KeyUsageModel, parameters, extension, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            [],
            [("value_error", ("value",), "Value error, value must not be empty")],
        ),
        (
            ["crl_sign", "crl_sign"],
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, crl_sign: value must be unique",
                )
            ],
        ),
        (
            ["encipher_only"],
            [
                (
                    "value_error",
                    (),
                    "Value error, encipher_only and decipher_only can only be set when key_agreement is set",
                )
            ],
        ),
        (
            ["decipher_only"],
            [
                (
                    "value_error",
                    (),
                    "Value error, encipher_only and decipher_only can only be set when key_agreement is set",
                )
            ],
        ),
    ),
)
def test_key_usage_errors(parameters: dict[str, bool], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the KeyUsageModel."""
    assert_validation_errors(KeyUsageModel, {"value": parameters}, expected_errors)


@pytest.mark.parametrize("critical", (True, False))
@pytest.mark.parametrize(
    ("parameters", "extension"),
    (
        (
            {"template_id": NameOID.COMMON_NAME.dotted_string},
            x509.MSCertificateTemplate(
                template_id=NameOID.COMMON_NAME, major_version=None, minor_version=None
            ),
        ),
        (
            {"template_id": NameOID.COMMON_NAME.dotted_string, "major_version": None, "minor_version": None},
            x509.MSCertificateTemplate(
                template_id=NameOID.COMMON_NAME, major_version=None, minor_version=None
            ),
        ),
        (
            {"template_id": NameOID.COMMON_NAME.dotted_string, "major_version": 1, "minor_version": 2},
            x509.MSCertificateTemplate(template_id=NameOID.COMMON_NAME, major_version=1, minor_version=2),
        ),
    ),
)
def test_ms_certificate_template(
    critical: bool, parameters: dict[str, Any], extension: x509.MSCertificateTemplate
) -> None:
    """Test the MSCertificateTemplateModel."""
    assert_extension_model(MSCertificateTemplateModel, parameters, extension, critical)


@pytest.mark.parametrize("critical", (True, None))
@pytest.mark.parametrize(
    ("parameters", "extension"),
    (
        (
            {"permitted_subtrees": [GENERAL_NAME]},
            x509.NameConstraints(permitted_subtrees=[dns("example.com")], excluded_subtrees=None),
        ),
        (
            {"excluded_subtrees": [GENERAL_NAME]},
            x509.NameConstraints(permitted_subtrees=None, excluded_subtrees=[dns("example.com")]),
        ),
        (
            {
                "permitted_subtrees": [GENERAL_NAME],
                "excluded_subtrees": [{"type": "DNS", "value": "example.net"}],
            },
            x509.NameConstraints(
                permitted_subtrees=[dns("example.com")], excluded_subtrees=[dns("example.net")]
            ),
        ),
    ),
)
def test_name_constraints(
    critical: bool | None, parameters: dict[str, bool], extension: x509.KeyUsage
) -> None:
    """Test the NameConstraintsModel."""
    assert_extension_model(NameConstraintsModel, parameters, extension, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            {"value": {}},
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, At least one of permitted_subtrees and excluded_subtrees must not be None",
                )
            ],
        ),
        ({"value": {"permitted_subtrees": [GENERAL_NAME]}, "critical": False}, [MUST_BE_CRITICAL_ERROR]),
        (
            {"value": {"permitted_subtrees": [GENERAL_NAME] * 2, "excluded_subtrees": None}},
            [
                (
                    "value_error",
                    ("value", "permitted_subtrees"),
                    re.compile("Value error, .*: value must be unique"),
                )
            ],
        ),
        (
            {"value": {"permitted_subtrees": None, "excluded_subtrees": [GENERAL_NAME] * 2}},
            [
                (
                    "value_error",
                    ("value", "excluded_subtrees"),
                    re.compile("Value error, .*: value must be unique"),
                )
            ],
        ),
        (
            {"value": {"permitted_subtrees": None, "excluded_subtrees": None}},
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, At least one of permitted_subtrees and excluded_subtrees must not be None",
                )
            ],
        ),
    ),
)
def test_name_constraints_errors(parameters: dict[str, bool], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the NameConstraintsModel."""
    assert_validation_errors(NameConstraintsModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (True, None))
@pytest.mark.parametrize(
    ("require_explicit_policy", "inhibit_policy_mapping"),
    ((0, 0), (1, 1), (0, 5), (5, 0), (None, 0), (0, None)),
)
def test_policy_constraints(
    critical: bool | None, require_explicit_policy: int, inhibit_policy_mapping: int
) -> None:
    """Test the PolicyConstraintsModel."""
    value = {
        "require_explicit_policy": require_explicit_policy,
        "inhibit_policy_mapping": inhibit_policy_mapping,
    }
    extension_type = x509.PolicyConstraints(
        require_explicit_policy=require_explicit_policy, inhibit_policy_mapping=inhibit_policy_mapping
    )
    assert_extension_model(PolicyConstraintsModel, value, extension_type, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            {"value": {"require_explicit_policy": None, "inhibit_policy_mapping": None}},
            [
                (
                    "value_error",
                    ("value",),
                    "Value error, At least one of require_explicit_policy and inhibit_policy_mapping must "
                    "not be None",
                )
            ],
        ),
        (
            {"value": {"require_explicit_policy": 0, "inhibit_policy_mapping": 0}, "critical": False},
            [MUST_BE_CRITICAL_ERROR],
        ),
        (
            {"value": {"require_explicit_policy": -1, "inhibit_policy_mapping": -1}},
            [
                (
                    "greater_than_equal",
                    ("value", "require_explicit_policy"),
                    "Input should be greater than or equal to 0",
                ),
                (
                    "greater_than_equal",
                    ("value", "inhibit_policy_mapping"),
                    "Input should be greater than or equal to 0",
                ),
            ],
        ),
    ),
)
def test_policy_constraints_errors(parameters: dict[str, Any], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the PolicyConstraintsModel."""
    assert_validation_errors(PolicyConstraintsModel, parameters, expected_errors)


@pytest.mark.parametrize("critical", (True, False, None))
def test_ocsp_no_check(critical: bool | None) -> None:
    """Test the OCSPNoCheckModel."""
    assert_extension_model(OCSPNoCheckModel, None, x509.OCSPNoCheck(), critical)


@pytest.mark.parametrize("critical", (True, None))
def test_precert_poison(critical: bool | None) -> None:
    """Test the PrecertPoisonModel."""
    assert_extension_model(PrecertPoisonModel, None, x509.PrecertPoison(), critical)


def test_precert_poison_errors() -> None:
    """Test validation errors for the PolicyConstraintsModel."""
    assert_validation_errors(PrecertPoisonModel, {"critical": False}, [MUST_BE_CRITICAL_ERROR])


def test_precertificate_signed_certificate_timestamps(
    precertificate_signed_certificate_timestamps_pub: x509.Certificate,
) -> None:
    """Test the PrecertificateSignedCertificateModel."""
    ext = precertificate_signed_certificate_timestamps_pub.extensions.get_extension_for_class(
        x509.PrecertificateSignedCertificateTimestamps
    )
    assert PrecertificateSignedCertificateTimestampsModel.model_validate(ext)


def test_signed_certificate_timestamps(signed_certificate_timestamps_pub: x509.Certificate) -> None:
    """Test the SignedCertificatesTimestampModel.

    .. NOTE:: There currently is no certificate that has this extension, and we cannot create it either.
    """
    ext = signed_certificate_timestamps_pub.extensions.get_extension_for_class(
        x509.SignedCertificateTimestamps
    )
    assert SignedCertificateTimestampsModel.model_validate(ext.value)


@pytest.mark.parametrize(
    ("parameters", "extension"),
    (
        (
            [{"access_method": "ca_repository", "access_location": GENERAL_NAME}],
            x509.SubjectInformationAccess(
                [x509.AccessDescription(SubjectInformationAccessOID.CA_REPOSITORY, dns("example.com"))]
            ),
        ),
    ),
)
@pytest.mark.parametrize("critical", (False, None))
def test_subject_information_access(
    parameters: dict[str, Any], extension: x509.AuthorityInformationAccess, critical: bool | None
) -> None:
    """Test the SubjectInformationAccessModel."""
    assert_extension_model(SubjectInformationAccessModel, parameters, extension, critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        ({"value": []}, [("value_error", ("value",), "Value error, value must not be empty")]),
        (
            {
                "value": [
                    {"access_method": "ca_repository", "access_location": {"type": "DNS", "value": "ex.com"}}
                ]
                * 2
            },
            [("value_error", ("value",), re.compile("value must be unique$"))],
        ),
        (
            {
                "value": [{"access_method": "ca_repository", "access_location": GENERAL_NAME}],
                "critical": True,
            },
            [MUST_BE_NON_CRITICAL_ERROR],
        ),
        (
            {"value": [{"access_method": "ocsp", "access_location": GENERAL_NAME}]},
            [
                (
                    "value_error",
                    (),
                    f"Value error, {AuthorityInformationAccessOID.OCSP.dotted_string}: access_method "
                    "not acceptable for this extension.",
                )
            ],
        ),
    ),
)
def test_subject_information_access_errors(
    parameters: dict[str, Any], expected_errors: ExpectedErrors
) -> None:
    """Test validation errors for the SubjectInformationAccessModel."""
    assert_validation_errors(SubjectInformationAccessModel, parameters, expected_errors)


@pytest.mark.parametrize(
    ("digest", "extension"),
    (
        # (b"123", x509.SubjectKeyIdentifier(b"123")),
        (b"kA==", x509.SubjectKeyIdentifier(b"\x90")),
        ("kA==", x509.SubjectKeyIdentifier(b"\x90")),
        # (b"\x90", x509.SubjectKeyIdentifier(b"\x90")),  # non-utf8 character
    ),
)
@pytest.mark.parametrize("critical", (False, None))
def test_subject_key_identifier(
    digest: bytes, extension: x509.SubjectKeyIdentifier, critical: bool | None
) -> None:
    """Test the SubjectKeyIdentifierModel."""
    assert_extension_model(SubjectKeyIdentifierModel, digest, extension, critical)


def test_subject_key_identifier_errors() -> None:
    """Test validation errors for the SubjectKeyIdentifierModel."""
    assert_validation_errors(
        SubjectKeyIdentifierModel, {"critical": True, "value": b"kA=="}, [MUST_BE_NON_CRITICAL_ERROR]
    )


@pytest.mark.parametrize(
    ("parameters", "features"),
    (
        (["status_request"], [x509.TLSFeatureType.status_request]),
        (["OCSPMustStaple"], [x509.TLSFeatureType.status_request]),
        ([x509.TLSFeatureType.status_request], [x509.TLSFeatureType.status_request]),
        (["status_request_v2"], [x509.TLSFeatureType.status_request_v2]),
        (["MultipleCertStatusRequest"], [x509.TLSFeatureType.status_request_v2]),
        ([x509.TLSFeatureType.status_request_v2], [x509.TLSFeatureType.status_request_v2]),
        (
            ["status_request", x509.TLSFeatureType.status_request_v2],
            [x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2],
        ),
        (
            ["status_request", "MultipleCertStatusRequest"],
            [x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2],
        ),
        (
            [x509.TLSFeatureType.status_request_v2, "status_request"],
            [x509.TLSFeatureType.status_request_v2, x509.TLSFeatureType.status_request],
        ),
    ),
)
@pytest.mark.parametrize("critical", (True, False, None))
def test_tls_feature(
    parameters: list[str | x509.TLSFeatureType],
    features: list[x509.TLSFeatureType],
    critical: bool | None,
) -> None:
    """Test the TLSFeatureModel."""
    assert_extension_model(TLSFeatureModel, parameters, x509.TLSFeature(features), critical)


@pytest.mark.parametrize(
    ("parameters", "expected_errors"),
    (
        (
            {"value": []},
            [("value_error", ("value",), "Value error, value must not be empty")],
        ),
        (
            {"value": ["status_request", "status_request"]},
            [("value_error", ("value",), "Value error, status_request: value must be unique")],
        ),
        (
            {"value": [x509.TLSFeatureType.status_request_v2, x509.TLSFeatureType.status_request_v2]},
            [("value_error", ("value",), "Value error, status_request_v2: value must be unique")],
        ),
    ),
)
def test_tls_feature_errors(parameters: dict[str, bool], expected_errors: ExpectedErrors) -> None:
    """Test validation errors for the TLSFeatureModel."""
    assert_validation_errors(TLSFeatureModel, parameters, expected_errors)


@pytest.mark.parametrize(
    ("parameters", "extension_type"),
    (
        (
            {"value": b"MTIz", "oid": "1.2.3"},
            x509.UnrecognizedExtension(value=b"123", oid=x509.ObjectIdentifier("1.2.3")),
        ),
    ),
)
@pytest.mark.parametrize("critical", (True, False))
def test_unrecognized_extension(
    parameters: dict[str, Any],
    extension_type: x509.UnrecognizedExtension,
    critical: bool | None,
) -> None:
    """Test the TLSFeatureModel."""
    assert_extension_model(UnrecognizedExtensionModel, parameters, extension_type, critical)


def test_certificate_extension_list_type_adapter() -> None:
    """Test type adapter for lists of extensions."""
    assert CertificateExtensionModelList.validate_python([]) == []
    basic_constraints_model = BasicConstraintsModel(value=BasicConstraintsValueModel(ca=True, path_length=0))
    input_list = [
        basic_constraints_model.cryptography,
        basic_constraints_model,
        basic_constraints_model.model_dump(mode="json"),
        x509.Extension(
            oid=x509.ObjectIdentifier("1.2.3"),
            critical=True,
            value=x509.UnrecognizedExtension(oid=x509.ObjectIdentifier("1.2.3"), value=b"\x90"),
        ),
    ]
    expected_list = [
        basic_constraints_model,
        basic_constraints_model,
        basic_constraints_model,
        UnrecognizedExtensionModel(
            critical=True, value=UnrecognizedExtensionValueModel(oid="1.2.3", value=b"kA==")
        ),
    ]
    assert CertificateExtensionModelList.validate_python(input_list) == expected_list


def test_configurable_extension_models_completeness() -> None:
    """Test ConfigurableExtensionModel for completeness."""
    models: tuple[ExtensionModel[Any]] = get_args(get_args(ConfigurableExtensionModel)[0])
    model_types = [model.model_fields["type"].default for model in models]
    assert sorted(model_types) == sorted(constants.CONFIGURABLE_EXTENSION_KEY_OIDS)


def test_certificate_extension_models_completeness() -> None:
    """Test CertificateExtensionModel for completeness."""
    models: tuple[ExtensionModel[Any]] = get_args(get_args(CertificateExtensionModel)[0])
    model_types = [model.model_fields["type"].default for model in models]
    assert sorted(model_types) == sorted([*constants.CERTIFICATE_EXTENSION_KEY_OIDS, "unknown"])


def test_extension_model_oids() -> None:
    """Test EXTENSION_MODEL_OIDS constant for correctness and completeness."""
    actual_oids = sorted(EXTENSION_MODEL_OIDS.values(), key=lambda oid: oid.dotted_string)
    expected_oids = sorted(KNOWN_EXTENSION_OIDS, key=lambda oid: oid.dotted_string)
    assert actual_oids == expected_oids


def test_fixture_certs(any_cert: str) -> None:
    """Test Pydantic models with fixture data."""
    public_key: x509.Certificate = CERT_DATA[any_cert]["pub"]["parsed"]
    serialized_extensions = CERT_DATA[any_cert][("extensions")]
    actual_extensions = list(public_key.extensions)

    expected = CertificateExtensionModelList.validate_python(
        serialized_extensions, context={"validate_required_critical": False}
    )
    actual = CertificateExtensionModelList.validate_python(
        actual_extensions, context={"validate_required_critical": False}
    )
    assert expected == actual
