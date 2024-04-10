from datetime import datetime, timezone

from django_ca.pydantic import OtherNameModel

dt = datetime(2021, 10, 5, 22, 1, 4, tzinfo=timezone.utc)
OtherNameModel(oid="1.2.3", type="UTCTIME", value=dt)
