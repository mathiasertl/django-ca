from django_ca.pydantic import (
    AdmissionModel,
    AdmissionsModel,
    AdmissionsValueModel,
    ProfessionInfoModel,
)

AdmissionsModel(
    value=AdmissionsValueModel(
        admissions=[
            AdmissionModel(
                profession_infos=[ProfessionInfoModel(profession_items=["info"])]
            )
        ],
    )
)
