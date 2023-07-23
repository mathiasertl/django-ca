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

*****************
API documentation
*****************

You can always view the API documentation of your current **django-ca** version by viewing
https://example.com/django-ca/api/docs/. You can also download the current :download:`openapi.json
</_files/openapi.json>` directly.

Below is the documentation for the current version (note that responses are currently not rendered due to
`this bug <https://github.com/sphinx-contrib/openapi/issues/107>`_):

.. openapi:: /_files/openapi.json
