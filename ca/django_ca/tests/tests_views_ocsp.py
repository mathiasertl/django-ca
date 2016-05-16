# -*- coding: utf-8 -*-
#
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

import base64
import os

from django.conf.urls import url
from django.core.urlresolvers import reverse
from django.test import Client

from ..views import OCSPView
from .base import DjangoCAWithCertTestCase
from .base import fixtures_dir
from .base import override_settings


#openssl ocsp -CAfile files/ca.pem -issuer files/ca.pem -serial 123  -reqout file -resp_text
def _load_req(req):
    path = os.path.join(fixtures_dir, 'ocsp', req)
    with open(path, 'rb') as stream:
        return stream.read()

req1 = _load_req('req1')

urlpatterns = [
    url(r'^ocsp/(?P<data>[a-zA-Z0-9=+/]+)$', OCSPView.as_view(), name='get'),
]


@override_settings(ROOT_URLCONF=__name__)
class OCSPTestView(DjangoCAWithCertTestCase):
    @classmethod
    def setUpClass(cls):
        super(OCSPTestView, cls).setUpClass()
        cls.client = Client()

    def test_basic(self):
        data = base64.b64encode(req1).decode('utf-8')
        response = self.client.get(reverse('get', kwargs={'data': data}))
        self.assertEqual(response.status_code, 200)
