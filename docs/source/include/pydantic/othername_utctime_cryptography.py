from datetime import UTC, datetime

from asn1crypto.core import UTCTime
from cryptography import x509

dt = datetime(2021, 10, 5, 22, 1, 4, tzinfo=UTC)
value = UTCTime(dt).dump()  # equals b"\x0c\x0bsome_string"
x509.OtherName(type_id=x509.ObjectIdentifier("1.2.3"), value=value)
