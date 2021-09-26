import typing

import dns.rdata

from .exception import DNSException
from .rdtypes.ANY.A import A
from .rdtypes.ANY.TXT import TXT
from .rdatatype import RdataType

RdataTypeVar = typing.TypeVar("RdataTypeVar", bound=dns.rdata.Rdata)


class NXDOMAIN(DNSException):
    pass


class Answer(typing.Generic[RdataTypeVar]):
    def __iter__(self) -> typing.Iterator[RdataTypeVar]:
        ...

    def __len__(self) -> int:
        ...


@typing.overload
def resolve(
    qname: str,
    rdtype: typing.Literal["TXT", RdataType.TXT],
    rdclass: typing.Union[int, str] = 0,
    tcp: bool = False,
    source: typing.Optional[str] = None,
    raise_on_no_answer: bool = True,
    source_port: int = 0,
    lifetime: typing.Optional[float] = None,
    search : typing.Optional[bool] = None
) -> Answer[TXT]:
    ...


@typing.overload
def resolve(
    qname: str,
    rdtype: typing.Literal["A", RdataType.A],
    rdclass: typing.Union[int, str] = 0,
    tcp: bool = False,
    source: typing.Optional[str] = None,
    raise_on_no_answer: bool = True,
    source_port: int = 0,
    lifetime: typing.Optional[float] = None,
    search : typing.Optional[bool] = None
) -> Answer[A]:
    ...


class Resolver:
    ...


def reset_default_resolver() -> None:
    ...


default_resolver = Resolver
