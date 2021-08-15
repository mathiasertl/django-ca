import typing

import dns.rdata


class TXTBase(dns.rdata.Rdata):
    __slots__ = ['strings']

    strings: typing.Tuple[bytes, ...]
