from cryptography import x509
from cryptography.x509.oid import ExtensionOID

profession_info = x509.ProfessionInfo(
    naming_authority=None,
    profession_items=["info"],
    profession_oids=None,
    registration_number=None,
    add_profession_info=None,
)
admission = x509.Admission(
    admission_authority=None,
    naming_authority=None,
    profession_infos=[profession_info],
)
x509.Extension(
    critical=False,
    oid=ExtensionOID.ADMISSIONS,
    value=x509.Admissions(authority=None, admissions=[admission]),
)
