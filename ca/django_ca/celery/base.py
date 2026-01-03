# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Celery-related code (not tasks themselves)."""

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar, cast, get_type_hints, overload

from pydantic import BaseModel

from django_ca.conf import model_settings
from django_ca.typehints import JSON
from django_ca.utils import get_type_hint

if TYPE_CHECKING:
    # celery.local is defined in our stubs
    from celery.local import Proxy

log = logging.getLogger(__name__)

TaskParamSpec = ParamSpec("TaskParamSpec")
TaskReturnSpec = TypeVar("TaskReturnSpec")


@overload
def dummy_shared_task(
    func: Callable[TaskParamSpec, TaskReturnSpec],
) -> "Proxy[TaskParamSpec, TaskReturnSpec]": ...


@overload
def dummy_shared_task(
    *args: Any,
    **kwargs: Any,
) -> Callable[[Callable[TaskParamSpec, TaskReturnSpec]], "Proxy[TaskParamSpec, TaskReturnSpec]"]: ...


def dummy_shared_task(
    *args: Any,
    **kwargs: Any,
) -> "Proxy[TaskParamSpec, TaskReturnSpec] | Callable[[Callable[TaskParamSpec, TaskReturnSpec]], Proxy[TaskParamSpec, TaskReturnSpec]]":  # noqa: E501
    """Dummy decorator so that we can use the decorator whether celery is installed or not."""

    def create_shared_task(
        *_not_used: Any,  # pylint: disable=unused-argument
        **options: Any,
    ) -> Callable[[Callable[TaskParamSpec, TaskReturnSpec]], "Proxy[TaskParamSpec, TaskReturnSpec]"]:
        def __inner(
            func: Callable[TaskParamSpec, TaskReturnSpec],
        ) -> "Proxy[TaskParamSpec, TaskReturnSpec]":
            # We do not yet need this, but might come in handy in the future:
            # func.delay = lambda *a, **kw: func(*a, **kw)
            # func.apply_async = lambda *a, **kw: func(*a, **kw)

            func.delay = func  # type: ignore[attr-defined]
            return cast("Proxy[TaskParamSpec, TaskReturnSpec]", func)

        return __inner

    if len(args) == 1 and callable(args[0]):
        # called without braces, e.g.
        #   @shared_task
        #   def ...
        return create_shared_task(**kwargs)(args[0])

    # called WITH branches, e.g.
    #   @shared_task()
    #   def ...
    return create_shared_task(*args, **kwargs)


try:
    from celery import Task, shared_task
except ImportError:  # pragma: no cover
    shared_task = dummy_shared_task

    class Task:  # type: ignore[no-redef]
        """Fake base class in the case that Celery is not installed."""

        name: str = "fake_task"

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError("Tasks must define __call__.")

        def run(self, data: BaseModel | None) -> BaseModel | None:  # pragma: no cover
            """Dummy for run()."""
            # This becomes the task function
            raise NotImplementedError("Tasks must define the run method.")

        def delay(self, *args: Any, **kwargs: Any) -> Any:
            """Dummy for delay()."""
            raise NotImplementedError("Tasks must define delay.")


class CeleryMessageModel(BaseModel):
    """Base model class for all celery messages."""


class DjangoCaTask(Task):  # pylint: disable=abstract-method  # pylint complains about run()
    """Custom base class for Celery tasks."""

    def __call__(self, data: dict[str, JSON] | None = None) -> Any:
        log.error("celery: running __call__(*%s)", data)
        type_hints = get_type_hints(self.run)
        log.error("typehints: %s", type_hints)

        # Task defines a `data` argument
        if sorted(type_hints) == ["data", "return"]:
            type_hint = type_hints["data"]
            model_class, optional = get_type_hint(type_hint)
            if not issubclass(model_class, CeleryMessageModel):
                raise TypeError(f"{self.name}: {model_class}: Not a subclass of CeleryMessageModel.")
            if data is None and optional is False:
                raise TypeError(f"{self.name}: No data received but `data` argument is not optional.")

            if data is not None:
                model = model_class.model_validate(data)
                return super().__call__(data=model)
            return super().__call__()

        # Task does **not** define a `data` argument
        if tuple(type_hints) == ("return",):
            if data is not None:
                raise TypeError(f"{self.name}: data received but task does not define a `data` argument.")
            return super().__call__()

        # If the task defines any other type hint besides `data`, it is also an error.
        raise TypeError(f"{self.name}: Task does not define a `data` argument or defines extra arguments.")

    # TODO: return type annotation should be AsyncResult
    def delay(self, data: BaseModel | None = None) -> Any:
        log.error("celery: running delay(*%s)", data)
        kwargs = {}
        if isinstance(data, BaseModel):
            kwargs["data"] = data.model_dump(mode="json", exclude_unset=True)
        elif data is not None:  # Ensure that no invalid argument was passed at runtime
            raise TypeError(f"{self.name}: {data}: Not a model instance.")
        return super().delay(**kwargs)


def run_task(
    task: "Proxy[TaskParamSpec, TaskReturnSpec]",
    *args: "TaskParamSpec.args",
    **kwargs: "TaskParamSpec.kwargs",
) -> Any:
    """Function that passes `task` to celery or invokes it directly, depending on if Celery is installed."""
    eager = kwargs.pop("eager", False)

    if model_settings.CA_USE_CELERY is True and eager is False:
        return task.delay(*args, **kwargs)

    return task(*args, **kwargs)


__all__ = ["DjangoCaTask", "run_task", "shared_task"]
