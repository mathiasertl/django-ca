import typing

from webtest.forms import Form
from webtest.response import TestResponse


class DjangoWebtestResponse(TestResponse):
    status_code: int

    def follow(self) -> "DjangoWebtestResponse":
        ...

    @property
    def form(self) -> Form["DjangoWebtestResponse"]:
        ...

    @property
    def forms(self) -> typing.Dict[typing.Union[int, str], Form["DjangoWebtestResponse"]]:
        ...


class DjangoTestApp:
    def get(self, url: str, *args: typing.Any, **kwargs: typing.Any) -> DjangoWebtestResponse:
        ...


class WebTestMixin:
    app_class: typing.Type[DjangoTestApp]
    app: DjangoTestApp
