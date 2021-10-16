import typing


class Service:
    def __init__(
        self,
        executable_path: str,
        port: int = 0,
        service_args: typing.Optional[typing.List[str]] = None,
        log_path: str = "geckodriver.log",
        env: typing.Optional[typing.Dict[str, str]] = None
    ) -> None:
        ...
