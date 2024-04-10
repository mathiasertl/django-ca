from django_ca.pydantic import OtherNameModel

OtherNameModel(oid="1.2.3", type="INTEGER", value="0x0C")  # or pass 12 (equals 0x0C)
