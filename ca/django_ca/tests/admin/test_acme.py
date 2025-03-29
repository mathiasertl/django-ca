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

"""Test cases for ModelAdmin classes for ACME models."""

import typing

from django.test import Client
from django.utils import timezone

import pytest

from django_ca.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeCertificate,
    AcmeChallenge,
    AcmeOrder,
    CertificateAuthority,
)
from django_ca.tests.admin.assertions import assert_changelist_response
from django_ca.tests.base.mixins import StandardAdminViewTestCaseMixin
from django_ca.tests.base.typehints import DjangoCAModelTypeVar

PEM1 = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvP5N/1KjBQniyyukn30E
tyHz6cIYPv5u5zZbHGfNvrmMl8qHMmddQSv581AAFa21zueS+W8jnRI5ISxER95J
tNad2XEDsFINNvYaSG8E54IHMNQijVLR4MJchkfMAa6g1gIsJB+ffEt4Ea3TMyGr
MifJG0EjmtjkjKFbr2zuPhRX3fIGjZTlkxgvb1AY2P4AxALwS/hG4bsxHHNxHt2Z
s9Bekv+55T5+ZqvhNz1/3yADRapEn6dxHRoUhnYebqNLSVoEefM+h5k7AS48waJS
lKC17RMZfUgGE/5iMNeg9qtmgWgZOIgWDyPEpiXZEDDKeoifzwn1LO59W8c4W6L7
XwIDAQAB
-----END PUBLIC KEY-----"""
PEM2 = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8SCUVQqpTBRyryuu560
Q8cAi18Ac+iLjaSLL4gOaDEU9CpPi4l9yCGphnQFQ92YP+GWv+C6/JRp24852QbR
RzuUJqJPdDxD78yFXoxYCLPmwQMnToA7SE3SnZ/PW2GPFMbAICuRdd3PhMAWCODS
NewZPLBlG35brRlfFtUEc2oQARb2lhBkMXrpIWeuSNQtInAHtfTJNA51BzdrIT2t
MIfadw4ljk7cVbrSYemT6e59ATYxiMXalu5/4v22958voEBZ38TE8AXWiEtTQYwv
/Kj0P67yuzE94zNdT28pu+jJYr5nHusa2NCbvnYFkDwzigmwCxVt9kW3xj3gfpgc
VQIDAQAB
-----END PUBLIC KEY-----"""
ACME_SLUG_1 = "Mr6FfdD68lzx"
ACME_SLUG_2 = "DzW4PQ6L76Px"

THUMBPRINT1 = "U-yUM27CQn9pClKlEITobHB38GJOJ9YbOxnw5KKqU-8"
THUMBPRINT2 = "s_glgc6Fem0CW7ZioXHBeuUQVHSO-viZ3xNR8TBebCo"
TOKEN1 = "grhuo1-ZmUMD8_53lQMlUN1WeURMpYkSGq5_4r-1S7JNVF3a25_xcA2K3dGtyGjt"
TOKEN2 = "3vmQafd29ROOktb7wJO_kZ8bIBlqoasegI9ElyLVRyMre_OyEPvjKjkQRxfzWprS"
TOKEN3 = "gY-kE5LdgwZyFeUCbjQKaX5Eo2lMsgabeB-m8zQ6eirhJP1WpVhenAyB7Yn-7BIq"
CSR1 = "MIICbDCCAVQCAQIwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKZoFq9UCNpCAfqNrdD2za8W9xuS6PTZzE13iitAbex75cs894cyhvNvBsJgreQ0ZTzvEy9FDB7CSBKQebsnewcETG4v2E4QyhvEBsWEzlIYNmlXxwkQXoxy3vm4bavxIcya5Db9HPw0oo0wqUWyx_GsEu0hRGY-Ys9VPuq81w60kHiXhcwv2PQtgiDtJ-VJ4xycYMRyAzYr_R13YzMa4gXUf7Hk4hDPitG28VyVcO8f5CR0ogtzA0C3r1SdwceJog1YgQfHLbgOUDsQhfbUrBAR7Iq_3K-txkxVtzwZedjCFGjNXe4CIL6e-NDo5nbFyuNseCQjP7TXfvQxhtrCIlECAwEAAaAnMCUGCSqGSIb3DQEJDjEYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQArIgdF2oMuxtHSgNrAk1_stu1bmXrr9dZ-ewbkgBaMq_o5PGh7OY3TFcF-7Uk-lbuCayHX-FcNe7X8dPiWg62ajzR_RROGGII0QiROe1Z77jtJuurE1MXnzkgYuE0JU0_9luAHHQFSCv9Nr6rO8Xy6otZfcolqwtWzSf7puOiQ5fC6Jdq5W4UAvlBfO7mqlhO7G_XCcSuzjSa1OcWSgd9zsp5Z-xYpL_4EgqXCiUsMCZ0sLhH2FuEkTw_tPEgRVUBz0ro51jijmG2Mg2N3irGv58IoElz3_NwWQewpfkIKEWzWcoG31sFJxEJapi_NuwdYAcKvYFNdPMH994rNKVjL"  # NOQA: E501
CSR2 = "MIICbDCCAVQCAQIwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALpIUHFIMXJSJ6YfoTsDRUgut6AY6sdhprPBumVdJXoBbDUjSW4R1aJuXPXmQMDRo-D5Tkvxx7rxsWnOG3l3-vZi18Ortk27k_5f-6_7OdoujijZFYxq0T0hVvgDh47r-aY67q0-CfTNfCYRfAkbOZ8UpAbV6u0vynguHznacIywl2NB5wmlDTLBo0CYp2ElRDfaj-Syhh6fwMTpDXs43wQJelJvDjOgMAPbcW1CiSnamIt3nSxwQjSOrAs6r-nIZblgPsQCvjjuF55okC4tjDqMSk2Qtq5bQwh9OO-AX9xTFCBeH8rqycqgPkIustUsFJEbOayQa4w2JWumgysFATkCAwEAAaAnMCUGCSqGSIb3DQEJDjEYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQAxc3zi_S79F_M5I8SFR4IOfJOt1pU1z6tsGNcVeK_vN-8jCMuQiicBlEwcauxox7KO1czMFX_Ikq-W_ctc2RhqfD4GsU80KDrDLQarZ1KC6egSXrHcuYqTeqRdNtnExCCrzRlUzaB5kojUpmdnRJ48rFgoLHuTxPd47vqTQahzx0xl3xhM-VQmQFc-urvIcyYNR620qA9b84lOwmzT9duRjYIrAS1H2vRatNqRU8tDAhbuvu-_yU_U0lo3gQcK5NGLVR45qU-yr0SgYIKgfkL6E6W9B80xT5Qt4Py7WZCSvrUOLC2uco_jDODrY-xCky7Tbalu1_FEzF-nkSEDK_x0"  # NOQA: E501


class AcmeAdminTestCaseMixin(
    StandardAdminViewTestCaseMixin[DjangoCAModelTypeVar], typing.Generic[DjangoCAModelTypeVar]
):
    """Admin view mixin that creates all model instances for ACME."""

    @pytest.fixture
    def account_one(self, child: CertificateAuthority) -> AcmeAccount:
        """Fixture for an enabled account."""
        kid = self.absolute_uri(":acme-account", serial=child.serial, slug=ACME_SLUG_1)
        return AcmeAccount.objects.create(
            ca=child,
            contact="mailto:user@example.com",
            status=AcmeAccount.STATUS_VALID,
            kid=kid,
            terms_of_service_agreed=True,
            pem=PEM1,
            thumbprint=THUMBPRINT1,
            slug=ACME_SLUG_1,
        )

    @pytest.fixture
    def account_two(self, root: CertificateAuthority) -> AcmeAccount:
        """Fixture for a revoked account."""
        kid = self.absolute_uri(":acme-account", serial=root.serial, slug=ACME_SLUG_1)
        return AcmeAccount.objects.create(
            ca=root,
            contact="mailto:user@example.net",
            status=AcmeAccount.STATUS_REVOKED,
            kid=kid,
            terms_of_service_agreed=False,
            pem=PEM2,
            thumbprint=THUMBPRINT2,
            slug=ACME_SLUG_2,
        )

    @pytest.fixture
    def order_one(self, account_one: AcmeAccount) -> AcmeOrder:
        """Fixture for an order."""
        return AcmeOrder.objects.create(account=account_one, status=AcmeOrder.STATUS_VALID)

    @pytest.fixture
    def order_two(self, account_two: AcmeAccount) -> AcmeOrder:
        """Fixture for an order."""
        return AcmeOrder.objects.create(account=account_two, status=AcmeOrder.STATUS_PROCESSING)

    @pytest.fixture
    def authorization_one(self, order_one: AcmeOrder) -> AcmeAuthorization:
        """Fixture for an authorization."""
        return AcmeAuthorization.objects.create(
            order=order_one,
            type=AcmeAuthorization.TYPE_DNS,
            value="example.com",
            status=AcmeAuthorization.STATUS_PENDING,
            wildcard=True,
        )

    @pytest.fixture
    def authorization_two(self, order_two: AcmeOrder) -> AcmeAuthorization:
        """Fixture for an authorization."""
        return AcmeAuthorization.objects.create(
            order=order_two,
            type=AcmeAuthorization.TYPE_DNS,
            value="example.net",
            status=AcmeAuthorization.STATUS_VALID,
            wildcard=False,
        )

    @pytest.fixture
    def challenge_one(self, authorization_one: AcmeAuthorization) -> AcmeChallenge:
        """Fixture for an challenge."""
        return AcmeChallenge.objects.create(
            auth=authorization_one, status=AcmeChallenge.STATUS_PENDING, token=TOKEN1
        )

    @pytest.fixture
    def challenge_two(self, authorization_two: AcmeAuthorization) -> AcmeChallenge:
        """Fixture for an challenge."""
        return AcmeChallenge.objects.create(
            auth=authorization_two,
            status=AcmeChallenge.STATUS_VALID,
            token=TOKEN2,
            validated=timezone.now(),
            type=AcmeChallenge.TYPE_HTTP_01,
        )

    @pytest.fixture
    def challenge_three(self, authorization_two: AcmeAuthorization) -> AcmeChallenge:
        """Fixture for an challenge."""
        return AcmeChallenge.objects.create(
            auth=authorization_two,
            status=AcmeChallenge.STATUS_INVALID,
            token=TOKEN3,
            error="some-error",
            type=AcmeChallenge.TYPE_DNS_01,
        )

    @pytest.fixture
    def certificate_one(self, order_one: AcmeOrder) -> AcmeCertificate:
        """Fixture for a certificate."""
        return AcmeCertificate.objects.create(order=order_one)

    @pytest.fixture
    def certificate_two(self, order_two: AcmeOrder) -> AcmeCertificate:
        """Fixture for a certificate."""
        return AcmeCertificate.objects.create(order=order_two, csr=CSR1)


class TestAcmeAccountViews(AcmeAdminTestCaseMixin[AcmeAccount]):
    """Test standard views for :py:class:`~django_ca.models.AcmeAccount`."""

    model = AcmeAccount

    @pytest.fixture
    def change_object(self, account_one: AcmeAccount) -> AcmeAccount:
        """Fixture for the object in detail view."""
        return account_one

    @pytest.fixture
    def changelist_objects(self, account_one: AcmeAccount, account_two: AcmeAccount) -> list[AcmeAccount]:
        """Fixture for the objects in the changelist."""
        return [account_one, account_two]


class TestAcmeOrderViews(AcmeAdminTestCaseMixin[AcmeOrder]):
    """Test standard views for :py:class:`~django_ca.models.AcmeOrder`."""

    model = AcmeOrder

    @pytest.fixture
    def change_object(self, order_one: AcmeOrder) -> AcmeOrder:
        """Fixture for the object in detail view."""
        return order_one

    @pytest.fixture
    def changelist_objects(self, order_one: AcmeOrder, order_two: AcmeOrder) -> list[AcmeOrder]:
        """Fixture for the objects in the changelist."""
        return [order_one, order_two]

    def test_expired_filter(self, admin_client: Client, order_one: AcmeOrder, order_two: AcmeOrder) -> None:
        """Test the "expired" list filter."""
        url = self.model.admin_changelist_url
        assert_changelist_response(admin_client.get(f"{url}?expired=0"), order_one, order_two)
        assert_changelist_response(admin_client.get(f"{url}?expired=1"))


class TestAcmeAuthorizationViews(AcmeAdminTestCaseMixin[AcmeAuthorization]):
    """Test standard views for :py:class:`~django_ca.models.AcmeAuthorization`."""

    model = AcmeAuthorization

    @pytest.fixture
    def change_object(self, authorization_one: AcmeAuthorization) -> AcmeAuthorization:
        """Fixture for the object in detail view."""
        return authorization_one

    @pytest.fixture
    def changelist_objects(
        self, authorization_one: AcmeAuthorization, authorization_two: AcmeAuthorization
    ) -> list[AcmeAuthorization]:
        """Fixture for the objects in the changelist."""
        return [authorization_one, authorization_two]


class TestAcmeChallengeViews(AcmeAdminTestCaseMixin[AcmeChallenge]):
    """Test standard views for :py:class:`~django_ca.models.AcmeChallenge`."""

    model = AcmeChallenge

    @pytest.fixture
    def change_object(self, challenge_one: AcmeChallenge) -> AcmeChallenge:
        """Fixture for the object in detail view."""
        return challenge_one

    @pytest.fixture
    def changelist_objects(
        self, challenge_one: AcmeChallenge, challenge_two: AcmeChallenge, challenge_three: AcmeChallenge
    ) -> list[AcmeChallenge]:
        """Fixture for the objects in the changelist."""
        return [challenge_one, challenge_two, challenge_three]


class TestAcmeCertificateViews(AcmeAdminTestCaseMixin[AcmeCertificate]):
    """Test standard views for :py:class:`~django_ca.models.AcmeCertificate`."""

    model = AcmeCertificate

    @pytest.fixture
    def change_object(self, certificate_one: AcmeCertificate) -> AcmeCertificate:
        """Fixture for the object in detail view."""
        return certificate_one

    @pytest.fixture
    def changelist_objects(
        self, certificate_one: AcmeCertificate, certificate_two: AcmeCertificate
    ) -> list[AcmeCertificate]:
        """Fixture for the objects in the changelist."""
        return [certificate_one, certificate_two]
