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

"""Application configuration for django-ca."""

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from pydantic import BaseModel

from cryptography.hazmat.primitives.asymmetric import ec

from django.conf import settings as _settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed

from django_ca.pydantic.config import SettingsModel
from django_ca.typehints import SignatureHashAlgorithm

BaseModelTypeVar = TypeVar("BaseModelTypeVar", bound=BaseModel)


class SettingsProxyBase(Generic[BaseModelTypeVar]):
    """Reusable Pydantic model proxy that reloads on automatically when settings change.

    Implementers must set `settings_model` to the Pydantic model they want to use.

    Parameters
    ----------
    reload_on_change : bool, optional
        Set to ``False`` if you do not want to reload the underlying model when settings change during
        testing.
    """

    settings_model: type[BaseModelTypeVar]
    __settings__: BaseModelTypeVar

    def __init__(self, reload_on_change: bool = True) -> None:
        self.reload()

        # Connect signal handler to reload the underlying Pydantic model when settings change.
        if reload_on_change is True:  # pragma: no branch
            self._connect_settings_changed()

    def __dir__(self, object: Any = None) -> Iterable[str]:  # pylint: disable=redefined-builtin
        # Used by ipython for tab completion, see:
        #   http://ipython.org/ipython-doc/dev/config/integrating.html
        getters = [getter for getter in dir(self.settings_model) if getter.startswith("get_")]
        return list(super().__dir__()) + list(self.settings_model.model_fields) + getters

    def _connect_settings_changed(self) -> None:
        setting_changed.connect(self._reload_from_signal)

    def _reload_from_signal(self, **kwargs: Any) -> None:
        self.reload()

    def reload(self) -> None:
        """Reload settings model from django settings."""
        try:
            self.__settings__ = self.settings_model.model_validate(_settings)
        except ValueError as ex:
            raise ImproperlyConfigured(str(ex)) from ex

    def __getattr__(self, item: str) -> Any:
        return getattr(self.__settings__, item)


class SettingsProxy(SettingsProxyBase[SettingsModel]):
    """Proxy class to access settings from the model.

    This class exists to enable reloading of settings in test cases.
    """

    settings_model = SettingsModel
    __settings__: SettingsModel

    if TYPE_CHECKING:
        # pylint: disable=missing-function-docstring
        # Our custom mypy plugin currently does not proxy getter methods, as I couldn't get this to
        # work properly. We thus add some typehints here so that mypy (and PyCharm) finds these methods.
        def get_default_signature_hash_algorithm(self) -> SignatureHashAlgorithm: ...

        def get_default_dsa_signature_hash_algorithm(self) -> SignatureHashAlgorithm: ...

        def get_default_elliptic_curve(self) -> ec.EllipticCurve: ...


model_settings = SettingsProxy()
