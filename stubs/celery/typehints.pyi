from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar

TaskParamSpec = ParamSpec("TaskParamSpec")
TaskReturnSpec = TypeVar("TaskReturnSpec")
TaskType = Callable[TaskParamSpec, Any]
TaskFunc = Callable[TaskParamSpec, TaskReturnSpec]