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

"""Mixin classes for admin view test cases."""

import json
from typing import Any

from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.select import Select

from django_ca.models import Certificate
from django_ca.tests.base.mixins import AdminTestCaseMixin
from django_ca.tests.base.testcases import SeleniumTestCase


class CertificateAdminTestCaseMixin:
    """Mixin that defines the ``media_css`` property for certificates.

    This does **not** set the ``model`` property, as mypy then complains about incompatible types in base
    classes.
    """

    media_css: tuple[str, ...] = (
        "django_ca/admin/css/base.css",
        "django_ca/admin/css/certificateadmin.css",
    )


class CertificateModelAdminTestCaseMixin(  # pragma: no cover
    CertificateAdminTestCaseMixin, AdminTestCaseMixin[Certificate]
):
    """Specialized variant of :py:class:`~django_ca.tests.tests_admin.AdminTestCaseMixin` for certificates."""

    model = Certificate


class AddCertificateSeleniumTestCase(
    CertificateModelAdminTestCaseMixin, SeleniumTestCase
):  # pragma: no cover
    """Base class for testing adding certificates with Selenium."""

    load_cas = ("root",)

    def setUp(self) -> None:
        super().setUp()
        self.login()
        self.url = f"{self.live_server_url}{self.add_url}"

    def assertModified(self) -> None:  # pylint: disable=invalid-name
        """Assert that the field was modified."""
        self.assertEqual(self.key_value_field.get_attribute("data-modified"), "true")

    def assertNotModified(self) -> None:  # pylint: disable=invalid-name
        """Assert that the field was not modified."""
        self.assertNotEqual(self.key_value_field.get_attribute("data-modified"), "true")

    def assertChapterHasValue(self, chapter: WebElement, value: Any) -> None:  # pylint: disable=invalid-name
        """Assert that the given chapter has the given value."""
        loaded_value = json.loads(chapter.get_attribute("data-value"))  # type: ignore[arg-type]
        self.assertEqual(loaded_value, value)

    def initialize(self) -> None:
        """Load the page and find core elements.

        It's unknown why this doesn't work during setUp(), but it doesn't.
        """
        self.selenium.get(self.url)

        # Top-level element of the NameField
        # pylint: disable=attribute-defined-outside-init
        self.key_value_field = self.find(".field-subject .key-value-field")
        self.hidden_input = self.key_value_field.find_element(By.ID, "id_subject")
        self.key_value_list = self.key_value_field.find_element(By.CSS_SELECTOR, ".key-value-list")

    @property
    def value(self) -> list[dict[str, str]]:
        """Load the current value from the hidden input field."""
        return json.loads(self.hidden_input.get_attribute("value"))  # type: ignore[no-any-return,arg-type]

    @property
    def displayed_value(self) -> list[dict[str, str]]:
        """Load the currently displayed value from the key/value list."""
        selects = self.key_value_list.find_elements(By.CSS_SELECTOR, "select")
        inputs = self.key_value_list.find_elements(By.CSS_SELECTOR, "input")
        self.assertEqual(len(selects), len(inputs))

        return [
            {
                "oid": Select(s).first_selected_option.get_attribute("value"),  # type: ignore[dict-item]
                "value": i.get_attribute("value"),  # type: ignore[dict-item]
            }
            for s, i in zip(selects, inputs)
        ]
