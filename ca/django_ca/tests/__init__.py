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

import importlib

from django.test.signals import setting_changed

from .. import ca_settings
from .. import profiles


def reload_ca_settings(sender, setting, **kwargs):  # pragma: no cover
    # This method will be enabled once support for django<2.2 support is dropped, see notes in
    # django_ca.tests.base.override_settings.

    # WARNING:
    # * Do NOT reload any other modules here, as isinstance() no longer returns True for instances from
    #   reloaded modules
    # * Do NOT set module level attributes, as other modules will not see the new instance

    importlib.reload(ca_settings)
    profiles.profiles._reset()


setting_changed.connect(reload_ca_settings)
