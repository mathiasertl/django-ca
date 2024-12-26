from django_ca.pydantic import (
    AdmissionModel,
    AdmissionsModel,
    AdmissionsValueModel,
    GeneralNameModel,
    NamingAuthorityModel,
    ProfessionInfoModel,
)

AdmissionsModel(
    value=AdmissionsValueModel(
        authority=GeneralNameModel(type="URI", value="https://example.com"),
        admissions=[
            AdmissionModel(
                profession_infos=[ProfessionInfoModel(profession_items=["info"])]
            ),
            AdmissionModel(
                admission_authority=GeneralNameModel(
                    type="URI", value="https://example.com"
                ),
                naming_authority=NamingAuthorityModel(
                    id="1.2.3", url="https://naming.example.com", text="some text"
                ),
                profession_infos=[
                    ProfessionInfoModel(profession_items=["info"]),
                    ProfessionInfoModel(
                        naming_authority=NamingAuthorityModel(
                            id="1.2.3",
                            url="https://sub.naming.example.com",
                            text="naming authority for second info model",
                        ),
                        profession_items=["info one", "info two"],
                        profession_oids=["1.2.4", "1.2.5"],
                        registration_number="abc",
                        add_profession_info="kA==",
                    ),
                ],
            ),
        ],
    )
)
