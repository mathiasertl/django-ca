import dns.enum


class RdataClass(dns.enum.IntEnum):
    RESERVED0: int
    IN: int
    INTERNET: int
    NONE: int
    ANY: int
