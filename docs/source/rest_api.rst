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

****************************
Authentication/Authorization
****************************

The API uses standard Django users with HTTP Basic Authentication for *authentication* and Django permissions
are used for *authorization*.

The easiest way to add an API user is via the admin interface in the browser. Different permissions are
required per endpoint:

================================ =============================================================================
Required permission              endpoints
================================ =============================================================================
Can view Certificate Authority   * ``GET /api/ca/`` - List available certificate authorities
                                 * ``GET /api/ca/{serial}/`` - View certificate authority
Can change Certificate Authority * ``PUT /api/ca/{serial}/`` - Update certificate authority
Can sign Certificate             ``POST /api/ca/{serial}/sign/`` - Sign a certificate
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


*****************
API documentation
*****************

You can always view the API documentation of your current **django-ca** version by viewing
https://example.com/django-ca/api/docs/. You can also download the current :download:`openapi.json
</_files/openapi.json>` directly.

Below is the documentation for the current version (note that responses are currently not rendered due to
`this bug <https://github.com/sphinx-contrib/openapi/issues/107>`_):

.. openapi:: /_files/openapi.json

*****************
Utility functions
*****************

.. autofunction:: django_ca.api.utils.create_api_user
