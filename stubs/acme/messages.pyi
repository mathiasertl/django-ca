# pylint: skip-file
from collections.abc import Hashable
from datetime import datetime
from typing import Any
from typing import ClassVar
from typing import Dict
from typing import Optional
from typing import Tuple

import josepy as jose

from .challenges import Challenge
from .mixins import ResourceMixin


class _Constant(jose.JSONDeSerializable, Hashable):
    POSSIBLE_NAMES: Dict[str, "_Constant"]
    name: str

    def __init__(self, name: str) -> None:
        ...

    def __hash__(self) -> int:
        ...


class Status(_Constant):
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


class Registration(ResourceBody):
    contact: Tuple[str, ...]
    only_return_existing: bool
    terms_of_service_agreed: bool

    phone_prefix: ClassVar[str]
    email_prefix: ClassVar[str]

    @property
    def emails(self) -> Tuple[str, ...]:
        ...


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


class CertificateRequest(ResourceMixin, jose.JSONObjectWithFields):
    resource_type: str


class Order(ResourceBody):
    ...


class NewOrder(Order):
    ...


IDENTIFIER_FQDN: IdentifierType
