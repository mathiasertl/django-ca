# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>

# Register the setting_changed signal here. This should not be done in base.py, because then a test module
# that does not import base.py would not have the signal registered.

"""handle signal when reloading settings, so that ca_settings is also reloaded."""

import importlib
from typing import Any, Type

from django.test.signals import setting_changed

from .. import ca_settings, profiles


def reload_ca_settings(  # pylint: disable=unused-argument
    sender: Type[Any], setting: str, **kwargs: Any
) -> None:
    """Reload ca_settings module if the settings are changed."""
    # WARNING:
    # * Do NOT reload any other modules here, as isinstance() no longer returns True for instances from
    #   reloaded modules
    # * Do NOT set module level attributes, as other modules will not see the new instance

    importlib.reload(ca_settings)
    profiles.profiles._reset()  # pylint: disable=protected-access


setting_changed.connect(reload_ca_settings)
