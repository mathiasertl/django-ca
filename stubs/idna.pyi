# pylint: skip-file
from typing import Union


class IDNAError(UnicodeError):
    ...


def encode(
        s: Union[str, bytes, bytearray],
        strict: bool = False,
        uts46: bool = False,
        std3_rules: bool = False,
        transitional: bool = False
) -> bytes:
    ...
