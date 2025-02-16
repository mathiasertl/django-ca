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

"""Utility functions for loading settings."""

import importlib
import logging
import os
from collections.abc import Callable, Iterator
from inspect import isclass
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, Field, RootModel

from django.core.exceptions import ImproperlyConfigured
from django.urls import URLPattern, URLResolver, include, path, re_path
from django.views import View

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = False  # type: ignore[assignment]


def url_pattern_type_validator(value: Any) -> Any:
    """Validator for url pattern type."""
    if value == "path":
        return path
    if value == "re_path":
        return re_path
    return value  # pragma: no cover  # might even be actual function, in theory


class ViewModel(BaseModel):
    """Model for using path() or re_path()."""

    view: str
    initkwargs: dict[str, Any] = Field(default_factory=dict)


class IncludeModel(BaseModel):
    """Model for using include()."""

    module: str
    namespace: str | None = None


# TYPEHINT NOTE: mypy complains about kwargs. See https://github.com/pydantic/pydantic/issues/3125
class UrlPatternModel(BaseModel):  # type: ignore[no-redef]
    """Model used vor validating elements in EXTEND_URL_PATTERNS."""

    func: Annotated[Callable[..., URLPattern | URLResolver], BeforeValidator(url_pattern_type_validator)] = (
        path
    )
    route: str
    view: ViewModel | IncludeModel
    kwargs: dict[str, Any] = Field(default_factory=dict)
    name: str | None = None

    @property
    def parsed_view(self) -> Any:
        """Returning a parsed view, class or function-based."""
        if isinstance(self.view, IncludeModel):
            return include(self.view.module, namespace=self.view.namespace)

        module_name, view_name = self.view.view.rsplit(".", 1)
        module = importlib.import_module(module_name)
        view = getattr(module, view_name)
        if isclass(view) and issubclass(view, View):
            return view.as_view(**self.view.initkwargs)

        return view

    @property
    def pattern(self) -> URLResolver | URLPattern:
        """Return the full URL pattern."""
        # pylint: disable-next=redundant-keyword-arg  # false positive
        return self.func(self.route, self.parsed_view, kwargs=self.kwargs, name=self.name)


class UrlPatternsModel(RootModel[list[UrlPatternModel]]):
    """Root model used for validating the EXTEND_URL_PATTERNS setting."""

    root: list[UrlPatternModel]

    def __iter__(self) -> Iterator[UrlPatternModel]:  # type: ignore[override]
        return iter(self.root)


def load_secret_key(secret_key: str | None, secret_key_file: str | None) -> str:
    """Load SECRET_KEY from file if not set elsewhere."""
    if secret_key:
        return secret_key

    if secret_key_file and os.path.exists(secret_key_file):
        with open(secret_key_file, encoding="utf-8") as stream:
            return stream.read()
    raise ImproperlyConfigured("Unable to determine SECRET_KEY.")


def get_settings_files(base_dir: Path, paths: str) -> Iterator[Path]:
    """Get relevant settings files."""
    for settings_path in [base_dir / p for p in paths.split(":")]:
        if not settings_path.exists():
            raise ImproperlyConfigured(f"{settings_path}: No such file or directory.")

        if settings_path.is_dir():
            # exclude files that don't end with '.yaml' and any directories
            yield from sorted(
                [
                    settings_path / _f.name
                    for _f in settings_path.iterdir()
                    if _f.suffix == ".yaml" and not _f.is_dir()
                ]
            )
        else:
            yield settings_path

    settings_yaml = base_dir / "ca" / "settings.yaml"
    if settings_yaml.exists():
        yield settings_yaml


def load_settings_from_files(base_dir: Path) -> Iterator[tuple[str, Any]]:
    """Load settings from YAML files."""
    # TYPEHINT NOTE: mypy typehints this to a module in the initial import statement
    if yaml is False:  # type: ignore[comparison-overlap]
        return

    # CONFIGURATION_DIRECTORY is set by the SystemD ConfigurationDirectory= directive.
    settings_paths = os.environ.get("DJANGO_CA_SETTINGS", os.environ.get("CONFIGURATION_DIRECTORY", ""))

    settings_files = []
    extend_installed_apps = []
    extend_url_patterns = []

    for full_path in get_settings_files(base_dir, settings_paths):
        with open(full_path, encoding="utf-8") as stream:
            try:
                data = yaml.safe_load(stream)
            except Exception as ex:
                logging.exception(ex)
                raise ImproperlyConfigured(f"{full_path}: Invalid YAML.") from ex

        if data is None:
            pass  # silently ignore empty files
        elif not isinstance(data, dict):
            raise ImproperlyConfigured(f"{full_path}: File is not a key/value mapping.")
        else:
            settings_files.append(full_path)
            for setting_name, setting_value in data.items():
                if setting_name == "EXTEND_URL_PATTERNS":
                    extend_url_patterns += setting_value
                elif setting_name == "EXTEND_INSTALLED_APPS":
                    extend_installed_apps += setting_value
                else:
                    yield setting_name, setting_value

    yield "EXTEND_INSTALLED_APPS", extend_installed_apps
    yield "EXTEND_URL_PATTERNS", extend_url_patterns

    # ALSO yield the SETTINGS_FILES setting with the loaded files.
    yield "SETTINGS_FILES", tuple(settings_files)


def load_settings_from_environment() -> Iterator[tuple[str, Any]]:
    """Load settings from the environment."""
    for key, value in {k[10:]: v for k, v in os.environ.items() if k.startswith("DJANGO_CA_")}.items():
        if key == "SETTINGS":  # points to yaml files loaded in get_settings_files
            continue

        if key == "ALLOWED_HOSTS":
            yield key, value.split()
        elif key in ("CA_USE_CELERY", "CA_ENABLE_ACME", "CA_ENABLE_REST_API", "ENABLE_ADMIN"):
            yield key, parse_bool(value)
        else:
            yield key, value


def parse_bool(value: str) -> bool:
    """Parse a variable that is supposed to represent a boolean value."""
    return value.strip().lower() in ("true", "yes", "1")


def _set_db_setting(
    databases: dict[str, dict[str, Any]], name: str, env_name: str, default: str | None = None
) -> None:
    if databases["default"].get(name):
        return

    if os.environ.get(env_name):
        databases["default"][name] = os.environ[env_name]
    elif os.environ.get(f"{env_name}_FILE"):
        with open(os.environ[f"{env_name}_FILE"], encoding="utf-8") as env_stream:
            databases["default"][name] = env_stream.read()
    elif default is not None:
        databases["default"][name] = default


def update_database_setting_from_environment(databases: dict[str, dict[str, Any]]) -> None:
    """Update the DATABASES dict with Docker-style environment variables."""
    # use POSTGRES_* environment variables from the postgres Docker image
    if databases["default"]["ENGINE"] in (
        "django.db.backends.postgresql_psycopg2",
        "django.db.backends.postgresql",
    ):
        _set_db_setting(databases, "PASSWORD", "POSTGRES_PASSWORD", default="postgres")
        _set_db_setting(databases, "USER", "POSTGRES_USER", default="postgres")
        _set_db_setting(databases, "NAME", "POSTGRES_DB", default=databases["default"].get("USER"))

    # use MYSQL_* environment variables from the mysql Docker image
    if databases["default"]["ENGINE"] == "django.db.backends.mysql":
        _set_db_setting(databases, "PASSWORD", "MYSQL_PASSWORD")
        _set_db_setting(databases, "USER", "MYSQL_USER")
        _set_db_setting(databases, "NAME", "MYSQL_DATABASE")
