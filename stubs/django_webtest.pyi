import typing

from django.http import HttpResponse


class Form:
    def submit(self) -> "DjangoWebtestResponse":
        ...


class DjangoWebtestResponse:
    def follow(self) -> "DjangoWebtestResponse":
        ...

    @property
    def form(self) -> Form:
        ...


class DjangoTestApp:
    def get(self, url: str, *args: typing.Any, **kwargs: typing.Any) -> DjangoWebtestResponse:
        ...


class WebTestMixin:
    app_class: typing.Type[DjangoTestApp]
    app: DjangoTestApp
