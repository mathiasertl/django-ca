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

import os

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

from django_ca.tests.base.constants import GECKODRIVER_LOG_PATH, GECKODRIVER_PATH
from django_ca.tests.base.mixins import TestCaseMixin


class SeleniumTestCase(TestCaseMixin, StaticLiveServerTestCase):  # pragma: no cover
    """TestCase with some helper functions for Selenium."""

    # NOTE: coverage has weird issues all over this class
    virtual_display: Display
    selenium: WebDriver

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()

        if os.environ.get("VIRTUAL_DISPLAY") != "n":
            cls.virtual_display = Display(visible=False, size=(1024, 768))
            cls.virtual_display.start()

        service = Service(str(GECKODRIVER_PATH), log_output=str(GECKODRIVER_LOG_PATH))
        cls.selenium = Firefox(service=service)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.selenium.quit()
        if os.environ.get("VIRTUAL_DISPLAY") != "n":
            cls.virtual_display.stop()

        super().tearDownClass()

    def find(self, selector: str) -> WebElement:
        """Find an element by CSS selector."""
        return self.selenium.find_element(by=By.CSS_SELECTOR, value=selector)

    def find_by_tag(self, tag: str) -> WebElement:
        """Find an element by its tag (e.g. "body")."""
        return self.selenium.find_element(by=By.TAG_NAME, value=tag)

    @classmethod
    def login(cls, username: str = "admin", password: str = "admin") -> None:
        """Login the given user."""
        cls.selenium.get(f"{cls.live_server_url}{reverse('admin:login')}")
        cls.selenium.find_element(By.ID, "id_username").send_keys(username)
        cls.selenium.find_element(By.ID, "id_password").send_keys(password)
        cls.selenium.find_element(By.CSS_SELECTOR, 'input[type="submit"]').click()
        cls.wait_for_page_load()

    @classmethod
    def wait_for_page_load(cls, timeout: int = 2, poll_frequency: float = 0.1) -> None:
        """Wait for the page to load."""
        WebDriverWait(cls.selenium, timeout, poll_frequency=poll_frequency).until(
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
