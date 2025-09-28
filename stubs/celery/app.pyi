import typing
from typing import Callable

from celery.local import Proxy

from celery.typehints import TaskParamSpec, TaskReturnSpec

F = Callable[TaskParamSpec, TaskReturnSpec]

def shared_task(func: Callable[TaskParamSpec, TaskReturnSpec]) -> Proxy[TaskParamSpec, TaskReturnSpec]: ...
