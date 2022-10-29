import typing

from webtest.response import TestResponse

ResponseTypeVar = typing.TypeVar("ResponseTypeVar", bound=TestResponse)


class Field:
    value: str


class Checkbox(Field):
    checked: bool


class Hidden(Field):
    ...


class Select(Field):
    ...


class Submit(Field):
    ...


class Form(typing.Generic[ResponseTypeVar]):
    def __setitem__(self, key: str, value: str) -> None:
        ...

    @property
    def fields(self) -> typing.Dict[str, typing.List[Field]]:
        ...

    def submit(self) -> ResponseTypeVar:
        ...
