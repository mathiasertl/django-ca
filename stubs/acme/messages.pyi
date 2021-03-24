# pylint: skip-file
from collections.abc import Hashable
from datetime import datetime
from typing import Any
from typing import Dict
from typing import Optional

import josepy as jose
from .challenges import Challenge


class _Constant(jose.JSONDeSerializable, Hashable):
    POSSIBLE_NAMES: Dict[str, "_Constant"]
    name: str

    def __init__(self, name: str) -> None:
        ...

    def __hash__(self) -> int:
        ...


class IdentifierType(_Constant):
    ...


class Identifier(jose.JSONObjectWithFields):
    typ: IdentifierType
    value: str

    def __init__(self, typ: IdentifierType, value: str) -> None:
        ...


class ResourceBody(jose.JSONObjectWithFields):
    resource_type: str


class ChallengeBody(ResourceBody):
    def __init__(
        self,
        chall: Challenge,
        status: Optional[str] = None,
        validated: Optional[datetime] = None,
        error: Optional[Any] = None,
        _uri: Optional[str] = "",
        _url: Optional[str] = "",
    ):
        ...


class Authorization(ResourceBody):
    ...


class Order(ResourceBody):
    ...


class NewOrder(Order):
    ...


IDENTIFIER_FQDN: IdentifierType
