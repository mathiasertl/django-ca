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
# see <http://www.gnu.org/licenses/>.

"""
**django-ca** adds a few custom Django signals to important events to let you execute custom actions when
these events happen. Please see `Djangos documentation on signals
<https://docs.djangoproject.com/en/dev/ref/signals/>`_ for further information on how to use signals.

If you use **django-ca** as :ref:`standalone project <as-standalone>`, use the :ref:`CA_CUSTOM_APPS
<settings-ca-custom-apps>` setting to add a custom django app. Please see the `Django documentation on apps
<https://docs.djangoproject.com/en/dev/ref/applications/>`_ if you need help on writing Django apps.
"""

import django.dispatch

pre_create_ca = django.dispatch.Signal()
"""Called before a new certificate authority is created.

Parameters
----------

name : str
    The name of the future CA.
**kwargs
"""

post_create_ca = django.dispatch.Signal()
"""Called after a new certificate authority was created.

Parameters
----------

ca : :py:class:`~django_ca.models.CertificateAuthority`
    The certificate authority that was just created.
"""


pre_issue_cert = django.dispatch.Signal()
"""Called before a new certificate is issued.

Parameters
----------

ca
csr
**kwargs
    All additional parameters passed to :py:meth:`~django_ca.profiles.Profile.create_cert`, but normalized to
    expected values. For example, this signal will receive a :py:class:`~django_ca.extensions.KeyUsage`
    instance, regardless of how the parameter was actually passed.
"""

post_issue_cert = django.dispatch.Signal()
"""Called after a new certificate was issued.

Parameters
----------

cert : :py:class:`~django_ca.models.Certificate`
    The certificate that was just issued.
"""

pre_revoke_cert = django.dispatch.Signal()
"""Called before a certificate is revoked.

Parameters
----------

ca
csr
**kwargs
"""

post_revoke_cert = django.dispatch.Signal()
"""Called after a certificate was revoked

Parameters
----------

cert : :py:class:`~django_ca.models.Certificate`
    The certificate that was just revoked.
"""
