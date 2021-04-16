import typing

from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver

POLL_FREQUENCY: float = 0.5


class WebDriverWait:
    def __init__(
        self,
        driver: RemoteWebDriver,
        timeout: int,
        poll_frequency: float = POLL_FREQUENCY,
        ignored_exceptions: typing.Optional[typing.Iterable[typing.Type[Exception]]] = None
    ) -> None:
        ...

    def until(self, method: typing.Callable[[RemoteWebDriver], typing.Any], message: str = "") -> None:
        ...
