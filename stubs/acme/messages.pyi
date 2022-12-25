# pylint: skip-file
from abc import ABCMeta
from collections.abc import Hashable
from datetime import datetime
from typing import Any
from typing import ClassVar
from typing import Dict
from typing import Optional
from typing import Tuple

import josepy as jose

from .challenges import Challenge

class _Constant(jose.interfaces.JSONDeSerializable, Hashable, metaclass=ABCMeta):
    POSSIBLE_NAMES: Dict[str, "_Constant"]
    name: str

    def __init__(self, name: str) -> None: ...
    def __hash__(self) -> int: ...

class Status(_Constant, metaclass=ABCMeta): ...
class IdentifierType(_Constant, metaclass=ABCMeta): ...

class Identifier(jose.json_util.JSONObjectWithFields):
    typ: IdentifierType
    value: str

    def __init__(self, typ: IdentifierType, value: str) -> None: ...

class ResourceBody(jose.json_util.JSONObjectWithFields):
    resource_type: str

class Registration(ResourceBody):
    contact: Tuple[str, ...]
    status: str
    only_return_existing: bool
    terms_of_service_agreed: bool

    phone_prefix: ClassVar[str]
    email_prefix: ClassVar[str]

    @property
    def emails(self) -> Tuple[str, ...]: ...

class ChallengeBody(ResourceBody):
    def __init__(
        self,
        chall: Challenge,
        status: Optional[str] = None,
        validated: Optional[datetime] = None,
        error: Optional[Any] = None,
        _uri: Optional[str] = "",
        _url: Optional[str] = "",
    ): ...

class Authorization(ResourceBody): ...

class CertificateRequest(jose.json_util.JSONObjectWithFields):
    resource_type: str

class Order(ResourceBody): ...
class NewOrder(Order): ...

class Revocation(jose.json_util.JSONObjectWithFields):
    certificate: jose.util.ComparableX509
    reason: int

IDENTIFIER_FQDN: IdentifierType
