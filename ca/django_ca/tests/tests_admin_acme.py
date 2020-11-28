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

"""Test cases for ModelAdmin classes for ACME models."""

# pylint: disable=too-many-ancestors; with mixins we have many ancestors

from django.utils import timezone

from ..models import AcmeAccount
from ..models import AcmeAccountAuthorization
from ..models import AcmeCertificate
from ..models import AcmeChallenge
from ..models import AcmeOrder
from .base import DjangoCAWithCATestCase
from .tests_admin import StandardAdminViewTestMixin

PEM1 = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvP5N/1KjBQniyyukn30E
tyHz6cIYPv5u5zZbHGfNvrmMl8qHMmddQSv581AAFa21zueS+W8jnRI5ISxER95J
tNad2XEDsFINNvYaSG8E54IHMNQijVLR4MJchkfMAa6g1gIsJB+ffEt4Ea3TMyGr
MifJG0EjmtjkjKFbr2zuPhRX3fIGjZTlkxgvb1AY2P4AxALwS/hG4bsxHHNxHt2Z
s9Bekv+55T5+ZqvhNz1/3yADRapEn6dxHRoUhnYebqNLSVoEefM+h5k7AS48waJS
lKC17RMZfUgGE/5iMNeg9qtmgWgZOIgWDyPEpiXZEDDKeoifzwn1LO59W8c4W6L7
XwIDAQAB
-----END PUBLIC KEY-----'''
PEM2 = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8SCUVQqpTBRyryuu560
Q8cAi18Ac+iLjaSLL4gOaDEU9CpPi4l9yCGphnQFQ92YP+GWv+C6/JRp24852QbR
RzuUJqJPdDxD78yFXoxYCLPmwQMnToA7SE3SnZ/PW2GPFMbAICuRdd3PhMAWCODS
NewZPLBlG35brRlfFtUEc2oQARb2lhBkMXrpIWeuSNQtInAHtfTJNA51BzdrIT2t
MIfadw4ljk7cVbrSYemT6e59ATYxiMXalu5/4v22958voEBZ38TE8AXWiEtTQYwv
/Kj0P67yuzE94zNdT28pu+jJYr5nHusa2NCbvnYFkDwzigmwCxVt9kW3xj3gfpgc
VQIDAQAB
-----END PUBLIC KEY-----'''
ACME_SLUG_1 = 'Mr6FfdD68lzp'
ACME_SLUG_2 = 'DzW4PQ6L76PE'

THUMBPRINT1 = 'U-yUM27CQn9pClKlEITobHB38GJOJ9YbOxnw5KKqU-8'
THUMBPRINT2 = 's_glgc6Fem0CW7ZioXHBeuUQVHSO-viZ3xNR8TBebCo'
TOKEN1 = 'grhuo1-ZmUMD8_53lQMlUN1WeURMpYkSGq5_4r-1S7JNVF3a25_xcA2K3dGtyGjt'
TOKEN2 = '3vmQafd29ROOktb7wJO_kZ8bIBlqoasegI9ElyLVRyMre_OyEPvjKjkQRxfzWprS'
TOKEN3 = 'gY-kE5LdgwZyFeUCbjQKaX5Eo2lMsgabeB-m8zQ6eirhJP1WpVhenAyB7Yn-7BIq'
CSR1 = 'MIICbDCCAVQCAQIwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKZoFq9UCNpCAfqNrdD2za8W9xuS6PTZzE13iitAbex75cs894cyhvNvBsJgreQ0ZTzvEy9FDB7CSBKQebsnewcETG4v2E4QyhvEBsWEzlIYNmlXxwkQXoxy3vm4bavxIcya5Db9HPw0oo0wqUWyx_GsEu0hRGY-Ys9VPuq81w60kHiXhcwv2PQtgiDtJ-VJ4xycYMRyAzYr_R13YzMa4gXUf7Hk4hDPitG28VyVcO8f5CR0ogtzA0C3r1SdwceJog1YgQfHLbgOUDsQhfbUrBAR7Iq_3K-txkxVtzwZedjCFGjNXe4CIL6e-NDo5nbFyuNseCQjP7TXfvQxhtrCIlECAwEAAaAnMCUGCSqGSIb3DQEJDjEYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQArIgdF2oMuxtHSgNrAk1_stu1bmXrr9dZ-ewbkgBaMq_o5PGh7OY3TFcF-7Uk-lbuCayHX-FcNe7X8dPiWg62ajzR_RROGGII0QiROe1Z77jtJuurE1MXnzkgYuE0JU0_9luAHHQFSCv9Nr6rO8Xy6otZfcolqwtWzSf7puOiQ5fC6Jdq5W4UAvlBfO7mqlhO7G_XCcSuzjSa1OcWSgd9zsp5Z-xYpL_4EgqXCiUsMCZ0sLhH2FuEkTw_tPEgRVUBz0ro51jijmG2Mg2N3irGv58IoElz3_NwWQewpfkIKEWzWcoG31sFJxEJapi_NuwdYAcKvYFNdPMH994rNKVjL'  # NOQA: E501
CSR2 = 'MIICbDCCAVQCAQIwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALpIUHFIMXJSJ6YfoTsDRUgut6AY6sdhprPBumVdJXoBbDUjSW4R1aJuXPXmQMDRo-D5Tkvxx7rxsWnOG3l3-vZi18Ortk27k_5f-6_7OdoujijZFYxq0T0hVvgDh47r-aY67q0-CfTNfCYRfAkbOZ8UpAbV6u0vynguHznacIywl2NB5wmlDTLBo0CYp2ElRDfaj-Syhh6fwMTpDXs43wQJelJvDjOgMAPbcW1CiSnamIt3nSxwQjSOrAs6r-nIZblgPsQCvjjuF55okC4tjDqMSk2Qtq5bQwh9OO-AX9xTFCBeH8rqycqgPkIustUsFJEbOayQa4w2JWumgysFATkCAwEAAaAnMCUGCSqGSIb3DQEJDjEYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAxc3zi_S79F_M5I8SFR4IOfJOt1pU1z6tsGNcVeK_vN-8jCMuQiicBlEwcauxox7KO1czMFX_Ikq-W_ctc2RhqfD4GsU80KDrDLQarZ1KC6egSXrHcuYqTeqRdNtnExCCrzRlUzaB5kojUpmdnRJ48rFgoLHuTxPd47vqTQahzx0xl3xhM-VQmQFc-urvIcyYNR620qA9b84lOwmzT9duRjYIrAS1H2vRatNqRU8tDAhbuvu-_yU_U0lo3gQcK5NGLVR45qU-yr0SgYIKgfkL6E6W9B80xT5Qt4Py7WZCSvrUOLC2uco_jDODrY-xCky7Tbalu1_FEzF-nkSEDK_x0'  # NOQA: E501


class AcmeAccountViewsTestCase(StandardAdminViewTestMixin, DjangoCAWithCATestCase):
    """Test standard views for :py:class:`~django_ca.models.AcmeAccount`."""
    model = AcmeAccount

    def setUp(self):
        super().setUp()
        self.kid1 = 'http://example.com%s' % self.absolute_uri(
            ':acme-account', serial=self.cas['child'].serial, slug=ACME_SLUG_1)
        self.account1 = AcmeAccount.objects.create(
            ca=self.cas['child'], contact=self.email, status=AcmeAccount.STATUS_VALID,
            terms_of_service_agreed=True, pem=PEM1, thumbprint=THUMBPRINT1, slug=ACME_SLUG_1,
            acme_kid=self.kid1)
        self.kid2 = 'http://example.com%s' % self.absolute_uri(
            ':acme-account', serial=self.cas['root'].serial, slug=ACME_SLUG_1)
        self.account2 = AcmeAccount.objects.create(
            ca=self.cas['root'], contact=self.email, status=AcmeAccount.STATUS_REVOKED,
            terms_of_service_agreed=False, pem=PEM2, thumbprint=THUMBPRINT2, slug=ACME_SLUG_2,
            acme_kid=self.kid2)


class AcmeOrderViewsTestCase(AcmeAccountViewsTestCase):
    """Test standard views for :py:class:`~django_ca.models.AcmeOrder`."""
    model = AcmeOrder

    def setUp(self):
        super().setUp()
        self.order1 = AcmeOrder.objects.create(account=self.account1, status=AcmeOrder.STATUS_VALID)
        self.order2 = AcmeOrder.objects.create(account=self.account1, status=AcmeOrder.STATUS_PROCESSING)


class AcmeAccountAuthorizationViewsTestCase(AcmeOrderViewsTestCase):
    """Test standard views for :py:class:`~django_ca.models.AcmeAccountAuthorization`."""
    model = AcmeAccountAuthorization

    def setUp(self):
        super().setUp()
        self.auth1 = AcmeAccountAuthorization.objects.create(
            order=self.order1, type=AcmeAccountAuthorization.TYPE_DNS, value='example.com',
            status=AcmeAccountAuthorization.STATUS_PENDING, wildcard=True)
        self.auth2 = AcmeAccountAuthorization.objects.create(
            order=self.order2, type=AcmeAccountAuthorization.TYPE_DNS, value='example.net',
            status=AcmeAccountAuthorization.STATUS_VALID, wildcard=False)


class AcmeChallengeViewsTestCase(AcmeAccountAuthorizationViewsTestCase):
    """Test standard views for :py:class:`~django_ca.models.AcmeChallenge`."""
    model = AcmeChallenge

    def setUp(self):
        super().setUp()
        self.chall1 = AcmeChallenge.objects.create(
            auth=self.auth1, status=AcmeChallenge.STATUS_PENDING, token=TOKEN1)
        self.chall2 = AcmeChallenge.objects.create(
            auth=self.auth2, status=AcmeChallenge.STATUS_VALID, token=TOKEN2, validated=timezone.now(),
            type=AcmeChallenge.TYPE_HTTP_01
        )
        self.chall3 = AcmeChallenge.objects.create(
            auth=self.auth2, status=AcmeChallenge.STATUS_INVALID, token=TOKEN3, error='some-error',
            type=AcmeChallenge.TYPE_DNS_01
        )


class AcmeCertificateViewsTestCase(AcmeChallengeViewsTestCase):
    """Test standard views for :py:class:`~django_ca.models.AcmeCertificate`."""
    model = AcmeCertificate

    def setUp(self):
        super().setUp()
        self.cert1 = AcmeCertificate.objects.create(order=self.order1)
        self.cert2 = AcmeCertificate.objects.create(order=self.order2, csr=CSR1)
