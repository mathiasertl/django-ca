import typing

WebElementTypeVar = typing.TypeVar("WebElementTypeVar", bound="WebElement")


class WebElement:
    def clear(self) -> None:
        ...

    def click(self) -> None:
        ...

    def get_attribute(self, name: str) -> typing.Optional[str]:
        ...

    def find_element(self, by: str, value: str) -> WebElementTypeVar:
        ...

    def find_element_by_css_selector(self: WebElementTypeVar, css_selector: str) -> WebElementTypeVar:
        ...

    def is_selected(self) -> bool:
        ...

    def send_keys(self, *value: str) -> None:
        ...

    @property
    def text(self) -> str:
        ...
