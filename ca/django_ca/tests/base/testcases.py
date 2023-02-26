# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Some common base classes for test cases."""

from django.conf import settings
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import TestCase
from django.urls import reverse

from pyvirtualdisplay import Display
from selenium.webdriver import Firefox
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.webdriver import WebDriver
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.wait import WebDriverWait

from django_ca.tests.base.mixins import TestCaseMixin


class SeleniumTestCase(TestCaseMixin, StaticLiveServerTestCase):  # pragma: no cover
    """TestCase with some helper functions for Selenium."""

    # NOTE: coverage has weird issues all over this class
    vdisplay: Display
    selenium: WebDriver

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        if settings.SKIP_SELENIUM_TESTS:
            return

        if settings.VIRTUAL_DISPLAY:
            cls.vdisplay = Display(visible=False, size=(1024, 768))
            cls.vdisplay.start()

        service = Service(settings.GECKODRIVER_PATH, log_path=settings.GECKODRIVER_LOG_PATH)
        cls.selenium = Firefox(service=service)

    @classmethod
    def tearDownClass(cls) -> None:
        if settings.SKIP_SELENIUM_TESTS:
            super().tearDownClass()
            return

        cls.selenium.quit()
        if settings.VIRTUAL_DISPLAY:
            cls.vdisplay.stop()
        super().tearDownClass()

    def find(self, selector: str) -> WebElement:
        """Find an element by CSS selector."""
        return self.selenium.find_element(by=By.CSS_SELECTOR, value=selector)

    def find_by_tag(self, tag: str) -> WebElement:
        """Find an element by its tag (e.g. "body")."""
        return self.selenium.find_element(by=By.TAG_NAME, value=tag)

    def login(self, username: str = "admin", password: str = "admin") -> None:
        """Login the given user."""
        self.selenium.get(f"{self.live_server_url}{reverse('admin:login')}")
        self.find("#id_username").send_keys(username)
        self.find("#id_password").send_keys(password)
        self.find('input[type="submit"]').click()
        self.wait_for_page_load()

    def wait_for_page_load(self, wait: int = 2) -> None:
        """Wait for the page to load."""
        WebDriverWait(self.selenium, wait).until(
            lambda driver: driver.find_element(by=By.TAG_NAME, value="body")
        )


class AcmeTestCase(TestCaseMixin, TestCase):  # pragma: no cover
    """Basic test case that loads root and child CA and enables ACME for the latter."""

    load_cas = (
        "root",
        "child",
    )

    def setUp(self) -> None:
        super().setUp()
        self.ca = self.cas["child"]
        self.ca.acme_enabled = True
        self.ca.save()
