# pylint: skip-file
import abc
from typing import Any
from typing import Callable
from typing import Dict
from typing import Generic
from typing import Optional
from typing import TypeVar

T = TypeVar('T')


def decode_b64jose(data: str, size: Optional[int] = None, minimum: Optional[bool] = False) -> bytes:
    ...


class Field(Generic[T]):
    def __init__(
        self,
        json_name: str,
        default: Optional[T] = None,
        omitempty: Optional[bool] = False,
        decoder: Optional[Callable[[str], T]] = None,
        encoder: Optional[Callable[[T], str]] = None
    ) -> None:
        ...

    @classmethod
    def fdec(cls, value: str) -> T:
        ...


class JSONObjectWithFields:
    _fields: Dict[str, Field[Any]]


class JSONDeSerializable(abc.ABC):
    ...


class TypedJSONObjectWithFields(JSONObjectWithFields):
    ...
