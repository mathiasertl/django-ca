from selenium.webdriver.remote.webelement import WebElement


class WebDriver:
    def find_element(self, by: str, value: str) -> WebElement:
        ...

    def find_element_by_css_selector(self, css_selector: str) -> WebElement:
        ...

    def find_element_by_tag_name(self, name: str) -> WebElement:
        ...

    def get(self, url: str) -> None:
        ...

    def implicitly_wait(self, time_to_wait: int) -> None:
        ...

    def quit(self) -> None:
        ...
