import typing

from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.remote.webdriver import WebDriver as RemoteWebDriver
from selenium.webdriver.remote.webelement import WebElement

from .service import Service


class WebDriver(RemoteWebDriver):
    def __init__(
        self,
        firefox_profile: typing.Optional[typing.Union[FirefoxProfile, str]] = None,
        firefox_binary: typing.Optional[typing.Union[FirefoxBinary, str]] = None,
        timeout: int = 30,
        capabilities: typing.Optional[typing.Dict[str, str]] = None,  # value is just a guess
        proxy: typing.Optional[typing.Any] = None,  # don't care
        executable_path: str = "geckodriver",
        options: typing.Optional[Options] = None,
        service: typing.Optional[Service] = None,
        service_log_path: str = "geckodriver.log",
        firefox_options: typing.Optional[Options] = None,
        service_args: typing.Optional[typing.List[str]] = None,  # str is just a guess
        desired_capabilities: typing.Optional[typing.Dict[str, str]] = None,
        log_path: typing.Optional[str] = None,
        keep_alive: bool = True,
    ) -> None:
        ...

    def find_element(self, by: str, value: str) -> WebElement:
        ...
