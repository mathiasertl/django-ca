########
REST API
########

.. warning:: This feature is still experimental, incomplete and will change without any advance notice.

**django-ca** provides an optional REST API based on `Django Ninja
<https://django-ninja.rest-framework.com/>`_. It allows you to list certificate authorities and certificates,
as well as sign and revoke certificates. The API is available at the ``/api/`` sub path. So if you
installed **django-ca** at https://example.com/django-ca/, the API is available at
https://example.com/django-ca/api/, with Open API documentation available at
https://example.com/django-ca/api/docs/.

The API is disabled by default and depending how you installed **django-ca**, you might have to install
additional dependencies manually.

************
Installation
************

The REST API requires the ``api`` extra to be installed.

For example, if you use **django-ca** as Django app, simply install it with:

.. code-block:: console

   $ pip install django-ca[api]

The Docker image already has everything installed, so you don't need to take any extra steps if you use Docker
or Docker Compose.

**************
Enable the API
**************

To enable the API, you need to set the :ref:`settings-ca-enable-rest-api` setting to ``True``.

You must also enable API access individually for every certificate authority. This can be done via the admin
interface or via the command line. The exact invocation depends on how you installed **django-ca**:

.. tab:: Django app

   .. code-block:: console

      user@host:~$ python manage.py list_cas  # Get CA serial
      E4:7C:17:... - Root
      user@host:~$ python manage.py edit_ca --api-enable E4:7C:17:...

.. tab:: from source

   .. code-block:: console

      user@host:~$ django-ca list_cas  # Get CA serial
      E4:7C:17:... - Root
      user@host:~$ django-ca edit_ca --api-enable E4:7C:17:...

.. tab:: with Docker

   .. code-block:: console

      user@host:~$ docker exec backend manage list_cas  # Get CA serial
      E4:7C:17:... - Root
      user@host:~$ docker exec backend manage edit_ca --api-enable E4:7C:17:...

.. tab:: with Docker Compose

   .. code-block:: console

      user@host:~/ca/$ docker compose exec backend manage list_cas  # Get CA serial
      E4:7C:17:... - Root
      user@host:~/ca/$ docker compose exec backend manage edit_ca --api-enable E4:7C:17:...

******************
Create an API user
******************

The API uses the built in Django users and permissions and HTTP Basic Authentication.

The easiest way to add a user is via the Django admin interface. The following permissions are required:

================================ =============================================================================
Required permission              endpoints
================================ =============================================================================
Can view Certificate Authority   * ``GET /api/ca/`` - List available certificate authorities
                                 * ``GET /api/ca/{serial}/`` - View certificate authority
Can change Certificate Authority * ``PUT /api/ca/{serial}/`` - Update certificate authority
Can sign Certificate             * ``POST /api/ca/{serial}/sign/`` - Sign a certificate
                                 * ``GET /api/ca/{serial}/orders/{order}/`` - Certificate order information
Can view Certificate             * ``GET /ca/{serial}/certs/`` - List certificates
                                 * ``GET /ca/{serial}/certs/{certificate_serial}/`` - View certificate
Can revoke Certificate           ``POST /ca/{serial}/revoke/{certificate_serial}/`` - Revoke certificate
================================ =============================================================================

If you do not use the admin interface, Django unfortunately does not provide an out-of-the box command to
create users, so you have to create them via :command:`manage.py shell` with our small helper function
:py:func:`~django_ca.api.utils.create_api_user`:

.. code-block:: python

    >>> from django_ca.api.utils import create_api_user
    >>> create_api_user('api-username', password='api-password')

**********
Quickstart
**********

The API is available under ``/django_ca/api/`` by default, view the documentation under
``/django_ca/api/docs`` (the ``/django_ca/`` prefix can be removed/modified with the
:ref:`settings-ca-url-path` setting).

In the following subsections you can learn how to use the API to issue a new certificate.

Create a CSR
============

The first step to retrieve a certificate is to create a private key and a certificate signing request (CSR).
Note that the contents of the CSR (e.g. the subject) is **not** used, as the information is provided in the
request itself.

.. tab:: curl

   .. code-block:: console

      user@host:~$ openssl genrsa -out priv.pem 4096
      user@host:~$ openssl req -new -key priv.pem -out csr.pem -utf8 -batch -subj '/'

.. tab:: Python

   .. code-block:: python

      >>> # Generate a private key and simplest possible CSR. See also:
      >>> #     https://cryptography.io/en/latest/x509/tutorial/
      >>> from cryptography import x509
      >>> from cryptography.hazmat.primitives import hashes, serialization
      >>> from cryptography.hazmat.primitives.asymmetric import rsa
      >>> from cryptography.x509.oid import NameOID
      >>> key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      >>> csr = x509.CertificateSigningRequestBuilder().subject_name(
      ...     x509.Name([])  # NOTE: The subject in the CSR is not used
      ... ).sign(key, hashes.SHA256())

Retrieve the serial of the CA
=============================

If you don't know the serial of the CA, you can retrieve it using one simple API endpoint:

.. tab:: curl

   .. code-block:: console

      user@host:~$ curl -u user https://ca.example.com/django_ca/api/ca/
      [{"serial": "E47C17...", ...}, ...]

.. tab:: Python

   Generate a CSR using cryptography and retrieve a new certificate for ``example.com`` using requests.

   .. code-block:: python

      >>> import requests
      >>> url = "https://ca.example.com/django_ca/api/ca/"
      >>> auth = ("user", "password")
      >>> serial = requests.get(url, auth=auth).json()[0]["serial"]

Create/poll certificate order
=============================

Request that the certificate authority issues a new certificate by creating a certificate order. You then poll
the order until the certificate is issued:

.. tab:: curl

   .. code-block:: console

      user@host:~$ curl \
      >     -u user \
      >     -H "Content-Type: application/json" \
      >     -d "{\"csr\": \"`awk '{printf "%s\\\\n", $0}' csr.pem`\", \"subject\": [{\"oid\": \"2.5.4.3\", \"value\": \"example.com\"}]}" \
      >     https://ca.example.com/django_ca/api/ca/E47C17.../sign/
      {"slug": "wj5ryHjWx4OT", "status": "pending", "serial": null, ...}
      user@host:~$ curl -u user https://ca.example.com/django_ca/api/ca/E47C17.../orders/wj5ryHjWx4OT/
      {"slug": "wj5ryHjWx4OT", "status": "issued", "serial": "3D6CA7...", ...}

.. tab:: Python

   .. code-block:: python

      >>> csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
      >>> subject = [{"oid": NameOID.COMMON_NAME.dotted_string, "value": "example.com"}]
      >>> order = requests.post(
      ...     f"{url}{serial}/sign/",
      ...     auth=auth,
      ...     json={"csr": csr_pem, "subject": subject}
      ... ).json()
      >>> status = order["status"]  # equals "pending"
      >>>
      >>> # Poll the order until finished (BEWARE: in this simplicity, this may loop indefinitely!)
      >>> order_url = f"{url}{serial}/orders/{order['slug']}/"
      >>> while status == "pending":
      ...     order = requests.get(order_url, auth=auth).json()
      ...     status = order["status"]

Retrieve certificate
====================

Once the certificate is issued, it is time to retrieve it:

.. tab:: curl

   .. code-block:: console

      user@host:~$ curl -u user https://ca.example.com/django_ca/api/ca/E47C17.../certs/3D6CA7.../
      {"serial": "3D6CA7...", "pem": "-----BEGIN CERTIFICATE-----\n...", ...}

.. tab:: Python

   .. code-block:: python

      >>> pem = requests.get(f"{url}{serial}/certs/{order['serial']}/", auth=auth).json()["pem"]


*****************
API documentation
*****************

You can always view the API documentation of your current **django-ca** version by viewing
https://example.com/django_ca/api/docs. You can also download the current :download:`openapi.json
</_files/openapi.json>` directly.

Below is the documentation for the current version (note that responses are currently not rendered due to
`this bug <https://github.com/sphinx-contrib/openapi/issues/107>`_):

.. openapi:: /_files/openapi.json

*****************
Utility functions
*****************

.. autofunction:: django_ca.api.utils.create_api_user
