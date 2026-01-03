from typing import Callable, Any, overload

from celery.local import Proxy

from celery.typehints import TaskParamSpec, TaskReturnSpec

F = Callable[TaskParamSpec, TaskReturnSpec]

@overload
def shared_task(
    func: "Callable[TaskParamSpec, TaskReturnSpec]",
) -> Proxy[TaskParamSpec, TaskReturnSpec]: ...

@overload
def shared_task(
    *args: Any,
    **kwargs: Any,
) -> Callable[[Callable[TaskParamSpec, TaskReturnSpec]], Proxy[TaskParamSpec, TaskReturnSpec]]: ...
