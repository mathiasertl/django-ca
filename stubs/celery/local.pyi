import typing

from .result import AsyncResult

F = typing.TypeVar("F", bound=typing.Callable[..., typing.Any])


class Proxy(typing.Generic[F]):
    # Calling the proxy directly is the same as the wrapped function
    __call__: F

    def delay(self, *args: typing.Any, **kwargs: typing.Any) -> AsyncResult:
        ...
