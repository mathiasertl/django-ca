import typing

from celery.app import shared_task

class Celery:
    # NOTE: Only documenting the one arg we actually use here
    def __init__(self, main: str) -> None: ...
    def config_from_object(
        self, obj: str, silent: bool = False, force: bool = False, namespace: typing.Optional[str] = None
    ) -> None: ...
    def autodiscover_tasks(
        self,
        packages: typing.Optional[typing.List[str]] = None,
        related_name: str = "tasks",
        force: bool = False,
    ) -> None: ...

__all__ = (
    "Celery",
    "shared_task",
)
