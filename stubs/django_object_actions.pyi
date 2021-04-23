import typing

from django.http import HttpRequest


class DjangoObjectActions:
    def get_change_actions(self, request: HttpRequest, object_id: int, form_url: str) -> typing.List[str]:
        ...
