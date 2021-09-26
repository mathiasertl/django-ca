import typing

import dns.rdata


class TXTBase(dns.rdata.Rdata):
    __slots__ = ['strings']

    strings: typing.Tuple[bytes, ...]

    def __init__(self, rdclass: int, rdtype: int, strings: typing.Iterable[bytes]) -> None:
        ...
