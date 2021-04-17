import typing

from selenium.webdriver.remote.webelement import WebElement


class Select:
    def __init__(self, webelement: WebElement) -> None:
        ...

    @property
    def all_selected_options(self) -> typing.List[WebElement]:
        ...

    def deselect_all(self) -> None:
        ...

    @property
    def options(self) -> typing.List[WebElement]:
        ...

    def select_by_value(self, value: str) -> None:
        ...
