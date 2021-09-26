import typing

import dns.enum


# NOTE: just stubbing out a few selected types here, real enum is much larger
class RdataType(dns.enum.IntEnum):
    TYPE0: int
    NONE: int
    A: int
    AAAA: int
    CAA: int
    CNAME: int
    MX: int
    NS: int
    PTR: int
    SOA: int
    SPF: int
    SRV: int
    TXT: int


TYPE0: typing.Literal[RdataType.TYPE0]
NONE: typing.Literal[RdataType.NONE]
A: typing.Literal[RdataType.A]
AAAA: typing.Literal[RdataType.AAAA]
CAA: typing.Literal[RdataType.CAA]
CNAME: typing.Literal[RdataType.CNAME]
MX: typing.Literal[RdataType.MX]
NS: typing.Literal[RdataType.NS]
PTR: typing.Literal[RdataType.PTR]
SOA: typing.Literal[RdataType.SOA]
SPF: typing.Literal[RdataType.SPF]
SRV: typing.Literal[RdataType.SRV]
TXT: typing.Literal[RdataType.TXT]
