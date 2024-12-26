from cryptography import x509
from cryptography.x509.oid import ExtensionOID

profession_info_one = x509.ProfessionInfo(
    naming_authority=None,
    profession_items=["info"],
    profession_oids=None,
    registration_number=None,
    add_profession_info=None,
)
profession_info_two = x509.ProfessionInfo(
    naming_authority=x509.NamingAuthority(
        id=x509.ObjectIdentifier("1.2.3"),
        url="https://sub.naming.example.com",
        text="naming authority for second info model",
    ),
    profession_items=["info one", "info two"],
    profession_oids=[x509.ObjectIdentifier("1.2.4"), x509.ObjectIdentifier("1.2.5")],
    registration_number="abc",
    add_profession_info=b"\x90",
)
admission_one = x509.Admission(
    admission_authority=None,
    naming_authority=None,
    profession_infos=[profession_info_one],
)
admission_two = x509.Admission(
    admission_authority=x509.UniformResourceIdentifier("https://example.com"),
    naming_authority=x509.NamingAuthority(
        id=x509.ObjectIdentifier("1.2.3"),
        url="https://naming.example.com",
        text="some text",
    ),
    profession_infos=[profession_info_one, profession_info_two],
)
x509.Extension(
    critical=False,
    oid=ExtensionOID.ADMISSIONS,
    value=x509.Admissions(
        authority=x509.UniformResourceIdentifier("https://example.com"),
        admissions=[admission_one, admission_two],
    ),
)
