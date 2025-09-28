from collections.abc import Callable
from typing import Generic, TypeVar

from celery.result import AsyncResult
from celery.typehints import TaskParamSpec, TaskReturnSpec

F = Callable[TaskParamSpec, TaskReturnSpec]

class Proxy(Generic[TaskParamSpec, TaskReturnSpec]):
    # Calling the proxy directly is the same as the wrapped function
    __call__: Callable[TaskParamSpec, TaskReturnSpec]

    def delay(self, *args: TaskParamSpec.args, **kwargs: TaskParamSpec.kwargs) -> AsyncResult: ...
