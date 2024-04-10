from django_ca.pydantic import OtherNameModel

# Or pass decoded b"\x61\x62\x63" for a value
OtherNameModel(oid="1.2.3", type="OctetString", value="616263")
