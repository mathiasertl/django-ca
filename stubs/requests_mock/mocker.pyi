import typing

from .adapter import _Matcher

T = typing.TypeVar("T", bound="Mocker")


class Mocker:
    def __init__(self, **kwargs: typing.Any) -> None:
        ...

    def __enter__(self: T) -> T:
        ...

    def __exit__(self, type: typing.Optional[Exception], value: typing.Any, traceback: typing.Any) -> None:
        ...

    def get(self, *args: typing.Any, **kwargs: typing.Any) -> _Matcher:
        ...
