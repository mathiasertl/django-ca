###############
Custom settings
###############

.. |bool| replace:: :ref:`bool <settings-types-bool>`
.. |dict| replace:: :ref:`dict <settings-types-collections>`
.. |int| replace:: :ref:`int <settings-types-int>`
.. |list| replace:: :ref:`list <settings-types-collections>`
.. |str| replace:: :ref:`str <settings-types-str>`
.. |timedelta| replace:: :ref:`timedelta <settings-types-timedelta>`

You can use any of the settings :doc:`understood by Django <django:ref/settings>` and **django-ca** provides
some of its own settings.

****************
How to configure
****************

If you use django-ca :doc:`as a Django app </quickstart/as_app>`, use :file:`settings.py` file, as you
normally would.

If you use the full django-ca project (e.g. if you :doc:`install from source </quickstart/from_source>`, or
use :doc:`Docker </quickstart/docker>` or :doc:`Docker Compose </quickstart/docker_compose>`), use
`YAML <https://en.wikipedia.org/wiki/YAML>`_ files that django-ca loads (in alphabetical order) from a
preconfigured directory. Please see the respective installation instructions for how to configure settings.

In the django-ca project, you can also use environment variables. The variable name is the same as the setting
but prefixed with ``DJANGO_CA_``. For example to set the ``CA_ENABLE_ACME`` setting, pass a
``DJANGO_CA_CA_ENABLE_ACME`` environment variable. Environment variables take precedence over the YAML
configuration files above.

The django-ca project also recognizes some environment variables to better integrate with other systems. See
:ref:`settings-global-environment-variables` for more information.

************************
Required Django settings
************************

If you use django-ca :doc:`as a Django app </quickstart/as_app>` the only required settings are the settings
any Django project requires anyway, most importantly ``DATABASES``, ``SECRET_KEY``, ``ALLOWED_HOSTS`` and
``STATIC_ROOT``.

If you :doc:`install from source </quickstart/from_source>`, you only have to set the ``DATABASES`` and
``SECRET_KEY`` settings. The ``CA_DEFAULT_HOSTNAME`` also configures the ``ALLOWED_HOSTS`` setting if not set
otherwise. Please see the `section on configuration <from-source-configuration>`_ for more information.

If you use :doc:`Docker </quickstart/docker>` or :doc:`docker-compose </quickstart/docker_compose>`, there
isn't really any standard Django setting you *have to* configure, as safe defaults are used. ``SECRETS_KEY``
is generated automatically, ``ALLOWED_HOSTS`` is set via ``CA_DEFAULT_HOSTNAME`` and the ``DATABASES`` setting
is automatically populated with environment variables also used by the PostgreSQL/MySQL containers.

******************
django-ca settings
******************

All settings used by **django-ca** start with the ``CA_`` prefix.

.. _settings-ca-crl-profiles:

CA_CRL_PROFILES
    .. pydantic-setting:: CA_CRL_PROFILES

    Each entry supports the following fields:

    ============================= =========== =========== ==============================================
    field                         type        default     comment
    ============================= =========== =========== ==============================================
    only_contains_ca_certs        |bool|      ``False``   True if CRL should contain only certificate
                                                          authorities.
    only_contains_user_certs      |bool|      ``False``   True if CRL should contain only end-entity
                                                          certificates.
    only_contains_attribute_certs |bool|      ``False``   No effect (attribute certs are not supported).
    only_some_reasons             |list|      ``None``    Optional set of
                                                          :class:`~cg:cryptography.x509.ReasonFlags`.
    expires                       |timedelta| 1 day       How long the CRL remains valid.
    OVERRIDES                     dict        ``{}``      See below.
    ============================= =========== =========== ==============================================

    Only one of `only_contains_ca_certs`, `only_contains_user_certs` and `only_contains_attribute_certs` is
    may be set to ``True``. If none are, all certificates (CAs and end-entity) are included.

    You may also specify an ``"OVERRIDES"`` key for a particular profile to specify custom behavior for select
    certificate authorities named by serial. It can set the same values as a general profile, plus the
    ``"skip"`` that disables the certificate authority for a particular profile. For example, to disable a
    profile for one certificate authority and use a non-standard expiry time for the other::

      {
          "user": {
               # other values
               OVERRIDES: {
                   "00:11:22": {"skip": True},
                   "33:44:55": {"expires": 3600},
               }
          }
      }

    .. versionchanged:: 2.1.0

      * The `only_some_reasons` parameter was added.
      * The `encodings` parameter was removed. Both supported encodings are now always available.

    .. versionchanged:: 2.3.0

      * The `scope` parameter to :ref:`settings-ca-crl-profiles` was removed in favor of the
        `only_contains_ca_certs`, `only_contains_user_certs` and `only_some_reasons` parameters.

.. _settings-ca-default-ca:

CA_DEFAULT_CA
    .. pydantic-setting:: CA_DEFAULT_CA

    For example, if you sign a certificate using the :ref:`manage.py sign_cert <cli_sign_certs>` command and do
    not pass the ``--ca`` parameter, the CA given here will be used. You can get a list of serials from the
    admin interface or via the ``manage.py list_cas`` command.

    .. WARNING::

        Some parts of **django-ca** will start throwing errors when attempting to use a default CA that is
        expired or disabled. So please make sure you keep this setting up to date.

    If this setting is *not* set, **django-ca** will select the CA that is currently usable (enabled, currently
    valid, not revoked) and and has an expiry furthest in the future.

.. _settings-ca-default-dsa-signature-hash-algorithm:

CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM
    .. pydantic-setting:: CA_DEFAULT_DSA_SIGNATURE_HASH_ALGORITHM

    Please see :py:attr:`~django_ca.typehints.SignatureHashAlgorithmName` for valid values for this setting.
    The default hash algorithm for ``RSA`` and ``EC`` certificates can be configured with
    :ref:`settings-ca-default-signature-hash-algorithm`.

    .. versionadded:: 1.23.0

.. _settings-ca-default-elliptic-curve:

CA_DEFAULT_ELLIPTIC_CURVE
    .. pydantic-setting:: CA_DEFAULT_ELLIPTIC_CURVE

    Please see :py:attr:`~django_ca.constants.ELLIPTIC_CURVE_TYPES` for a list of valid values.

    .. versionchanged:: 1.26.0

        This setting used to be called ``CA_DEFAULT_ECC_CURVE``.

.. _settings-ca-default-expires:

CA_DEFAULT_EXPIRES
    .. pydantic-setting:: CA_DEFAULT_EXPIRES

    Certificates issued via ACMEv2 are not affected by this setting, as :ref:`CA_ACME_DEFAULT_CERT_VALIDITY
    <CA_ACME_DEFAULT_CERT_VALIDITY>` is used there.

    An integer value will be parsed as a number of *days*.

    .. versionchanged:: 2.6.0

        The default value was changed to 100 days (from 365 days).

.. _settings-ca-default-hostname:

CA_DEFAULT_HOSTNAME
    .. pydantic-setting:: CA_DEFAULT_HOSTNAME

    If set, the default hostname will be used to automatically generate URLs for CRLs and OCSP services.  This
    setting *must not* include the protocol, as OCSP always uses HTTP (not HTTPS) and this setting might be
    used for other values in the future. For example:

    .. pydantic-setting:: CA_DEFAULT_HOSTNAME
        :example: 0

    .. include:: include/change_settings_warning.rst

.. _settings-ca-default-key-size:

CA_DEFAULT_KEY_SIZE
    .. pydantic-setting:: CA_DEFAULT_KEY_SIZE

    The value must be a power of two (e.g. ``2048``, ``4096``, ...) and no lower then ``1024``.

.. _settings-ca-default-name-order:

CA_DEFAULT_NAME_ORDER
   Default::

      (
         "dnQualifier", "countryName", "postalCode", "jurisdictionStateOrProvinceName",
         "localityName", "domainComponent", "organizationName", "organizationalUnitName",
         "title", "commonName", "uid", "emailAddress", "serialNumber"
      )

   .. versionadded:: 1.24.0

   Default order to use for x509 Names (such as the certificates subject). The value is used when signing
   certificates to normalize the order of x509 name fields in the certificates subject.

   This setting is used when signing certificates via ACMEv2 to determine the position of the
   CommonName field if the selected profile defines a subject fragment (see :ref:`profiles-subject` for more
   information).

   The setting is also used when signing certificates via the command-line to determine the position of the
   CommonName field if only subject alternative names are defined via the command-line and/or if the selected
   profile defines a subject fragment.

   On most applications, the order does not matter, but is relevant in LDAP applications.

   The value must be a ``tuple``, with the values being either a :py:class:`~cg:cryptography.x509.oid.NameOID`
   or a ``str``. String values must be one or the values listed in
   :py:attr:`~django_ca.constants.NAME_OID_TYPES` or the dotted string value of the OID:

   .. tab:: Python

      .. literalinclude:: /include/config/setting_ca_default_name_order.py
         :language: python

   .. tab:: YAML

      .. literalinclude:: /include/config/setting_ca_default_name_order.yaml
         :language: yaml

   The default is based on experience with existing certificates, as there is no known standard for an order.

   The value is used when signing certificates to normalize the order of x509 name fields such as the
   certificates subject and issuer field. On most applications, the order does not matter, but is relevant
   in LDAP applications.

.. _settings-ca-default-private-key-type:

CA_DEFAULT_PRIVATE_KEY_TYPE
    .. pydantic-setting:: CA_DEFAULT_PRIVATE_KEY_TYPE

    Note that this setting is *not* used when generating OCSP responder certificates, where the default
    private key type is the same as the certificate authority.

.. _settings-ca-default-profile:

CA_DEFAULT_PROFILE
    .. pydantic-setting:: CA_DEFAULT_PROFILE

.. _settings-ca-default-signature-hash-algorithm:

CA_DEFAULT_SIGNATURE_HASH_ALGORITHM
    .. pydantic-setting:: CA_DEFAULT_SIGNATURE_HASH_ALGORITHM

    Please see :py:attr:`~django_ca.typehints.SignatureHashAlgorithmName` for valid values for this setting.

    Since certificate authorities that use a DSA key pair don't work well with a SHA-512 hash, the default can
    be configured separately using :ref:`settings-ca-default-dsa-signature-hash-algorithm`.

.. _settings-ca-default-storage-alias:

CA_DEFAULT_STORAGE_ALIAS
    .. pydantic-setting:: CA_DEFAULT_STORAGE_ALIAS

    The storage alias used by the :ref:`Storages key backend <storages_backend>` and the
    :ref:`Storages OCSP key backend <storages_ocsp-key-backend>` (the default key backends) to store
    private keys. The value defined here has to be an alias in `STORAGES
    <https://docs.djangoproject.com/en/dev/ref/settings/#storages>`_.

.. _settings-ca-default-subject:

CA_DEFAULT_SUBJECT
    .. pydantic-setting:: CA_DEFAULT_SUBJECT

    .. versionchanged:: 2.2.0

        Before 2.2.0, this value (and subjects in profiles) were a tuple ``tuple`` consisting of two-tuples
        naming the attribute type and value. The old format was deprecated since 1.29.0.

    .. Describe here the syntax of this value. Profiles describe how the value is used.

    The default subject for :doc:`/profiles` that don't define their own subject. You can use this setting to
    define a default subject for all profiles without having to define the subject in every profile.

    Please see :ref:`profiles-subject` for how this value is used when signing certificates.

    Note that when signing via the command-line or ACMEv2, the subject attributes of a certificate will be
    sorted according to :ref:`settings-ca-default-name-order`, regardless of the order given here.

    The value is a list or tuple of key/value mappings defining a name attribute:

    .. pydantic-setting:: CA_DEFAULT_SUBJECT
        :example: 0

    OID values can be any key from :py:attr:`~django_ca.constants.NAME_OID_TYPES` or a dotted string as
    documented in :py:class:`~cg:cryptography.x509.oid.NameOID`. The following example is equivalent to the
    above:

    .. pydantic-setting:: CA_DEFAULT_SUBJECT
        :example: 1

    If you use Python as a configuration format, the value can also be a :py:class:`x509.Name
    <cg:cryptography.x509.Name>` instance.  For convenience, you can also give :py:class:`x509.NameAttribute
    <cg:cryptography.x509.NameAttribute>` instances in the tuple defined above, or use an
    :py:class:`x509.ObjectIdentifier <cg:cryptography.x509.ObjectIdentifier>` as ``"oid"`` key:

    .. literalinclude:: /include/config/setting_default_subject_cryptography.py
        :language: python

.. _settings-ca-enable-rest-api:

CA_ENABLE_REST_API
   .. pydantic-setting:: CA_ENABLE_REST_API

   Set to ``True`` to enable the :doc:`experimental REST API </rest_api>`.

.. _settings-ca-key-backends:

CA_KEY_BACKENDS
   Default:

   .. tab:: Python

      .. literalinclude:: /include/config/settings_default_ca_key_backends.py
         :language: python

   .. tab:: YAML

      .. literalinclude:: /include/config/settings_default_ca_key_backends.yaml
         :language: YAML

   The backends available to store private keys. Currently, only file system storage is supported out of the
   box, see :doc:`Key backends </python/key_backends>` for a list of available backends and their options.

   The default ``StoragesBackend`` uses a storage alias called ``"django-ca"`` by default, so it implies that
   the `STORAGES <https://docs.djangoproject.com/en/dev/ref/settings/#storages>`_ setting has a "django-ca"
   alias defined. If you use the full project (e.g. installed with :doc:`from source
   </quickstart/from_source>`, :doc:`with Docker </quickstart/docker>` or :doc:`Docker Compose
   </quickstart/docker_compose>`), this will be the file system directory set by :ref:`settings-ca-dir`,
   unless you define your own storage backend. If you use django-ca :doc:`as Django app </quickstart/as_app>`,
   you have to define this storage alias.

.. _settings-ca-min-key-size:

CA_MIN_KEY_SIZE
   .. pydantic-setting:: CA_MIN_KEY_SIZE

   The value must be a power of two (e.g. ``2048``, ``4096``, ...) and no lower then ``1024``.

CA_NOTIFICATION_DAYS
    .. pydantic-setting:: CA_NOTIFICATION_DAYS

.. _settings-ca-ocsp-urls:

CA_OCSP_URLS
    .. pydantic-setting:: CA_OCSP_URLS

    A full example might look like this:

    .. pydantic-setting:: CA_OCSP_URLS
        :example: 0

.. _settings-ca-ocsp-key-backends:

CA_OCSP_KEY_BACKENDS
   Default:

   .. tab:: Python

      .. literalinclude:: /include/config/settings_default_ca_ocsp_key_backends.py
         :language: python

   .. tab:: YAML

      .. literalinclude:: /include/config/settings_default_ca_ocsp_key_backends.yaml
         :language: YAML

   Configuration for storing OCSP keys. See :ref:`ocsp_key_backends` for more information.

.. _settings-ca-ocsp-responder-certificate-renewal:

CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL
    .. pydantic-setting:: CA_OCSP_RESPONDER_CERTIFICATE_RENEWAL

    This setting is used by the :ref:`periodic task to regenerate OCSP responder certificates
    <periodic-tasks-explanation>` to determine if an OCSP responder certificate should be renewed or not.

    .. WARNING::

        The value must be *lower* then the frequency of the regular task *and* lower then the OCSP responder
        certificate validity that you configure with the ``--ocsp-responder-key-validity`` option to
        :command:`manage .py init_ca`/:command:`manage .py edit_ca`.

.. _settings-ca-passwords:

CA_PASSWORDS
    .. pydantic-setting:: CA_PASSWORDS

    This setting is used by the :ref:`Storages backend <storages_backend>` when using a CA private key that
    was encrypted (using :command:`manage init_ca --password ...`). The setting is required for automatically
    generating CRLs and OCSP keys for certificate authorities with encrypted private keys.

    .. NOTE::

        If you use Celery, the setting is only required for the Celery workers (which can run on a different
        host), the web application server (e.g. Gunicorn) does not need to use private keys in this case.

    Example:

    .. pydantic-setting:: CA_PASSWORDS
        :example: 0

.. _settings-ca-profiles:

CA_PROFILES
    .. pydantic-setting:: CA_PROFILES

    Add new profiles or change existing ones.  Please see :doc:`/profiles` for more information on profiles.

.. _settings-ca-use-celery:

CA_USE_CELERY
    .. pydantic-setting:: CA_USE_CELERY

    Using Celery is highly recommended for performance and security reasons. You may set this to ``False`` to
    disable the use of Celery despite it being installed. If disabled, long-running tasks (e.g. signing a
    certificate or accessing a HSM) will happen directly in the web application server (e.g. Gunicorn).

.. _settings-acme:

ACMEv2 settings
===============

.. _settings-acme-enable-acme:

CA_ENABLE_ACME
   .. pydantic-setting:: CA_ENABLE_ACME

   Note that even when enabled, you need to explicitly enable ACMEv2 support for a certificate authority
   either via the admin interface or via :doc:`the command-line interface </cli/cas>`.

.. _CA_ACME_DEFAULT_CERT_VALIDITY:

CA_ACME_DEFAULT_CERT_VALIDITY
    .. pydantic-setting:: CA_ACME_DEFAULT_CERT_VALIDITY

    An integer value will be parsed as a number of *days*.

    .. versionchanged:: 2.6.0

        The default value was changed to 45 days (from 90 days).

.. _CA_ACME_MAX_CERT_VALIDITY:

CA_ACME_MAX_CERT_VALIDITY
    .. pydantic-setting:: CA_ACME_MAX_CERT_VALIDITY

    The ACMEv2 protocol allows for clients to request a non-default validity time, but certbot currently
    does not expose this feature.

    An integer value will be parsed as a number of *days*.

.. _CA_ACME_ORDER_VALIDITY:

CA_ACME_ORDER_VALIDITY
    .. pydantic-setting:: CA_ACME_ORDER_VALIDITY

    An integer value will be parsed as a number of *days*. The maximum value is one day.

****************
Project settings
****************

Project settings are available if you use the full **django-ca** project (including if you use the Docker
container or via docker-compose). Many settings are _not_ prefixed with ``CA_``, because they configure how
Django itself works.

As any other setting, they can be set by using environment variables prefixed with ``DJANGO_CA_`` (Example: To
set ``LOG_LEVEL``, set the ``DJANGO_CA_LOG_LEVEL`` environment variable).

.. _settings-ca-dir:

CA_DIR
   Default: ``"files/"``

   Where the root certificate is stored. The default is a ``files`` directory in the same location as your
   ``manage.py`` file.

   This setting has no effect if you define a ``"django-ca"`` alias in `STORAGES
   <https://docs.djangoproject.com/en/dev/ref/settings/#storages>`_ (see also:
   :ref:`settings-ca-key-backends`).


CA_ENABLE_CLICKJACKING_PROTECTION
   Default: ``True``

   Set to ``False`` to disable :doc:`django:ref/clickjacking`. The setting influences if the
   ``XFrameOptionsMiddleware`` is added to the list of middlewares.  This setting is useful if the header is
   already set by the web server.

.. _settings-ca-url-path:

CA_URL_PATH
   Default: ``django_ca/``

   .. include:: include/change_settings_warning.rst

   To URL path to use for ACMEv2, OCSP, CRL and the API, but *not* the admin interface.

   If you use **django-ca** as app, the effect of this setting is achieved by the URL path given in your root
   URL conf.

.. _settings-enable-admin:

ENABLE_ADMIN
   Default: ``True``

   Set to ``False`` to disable the default Django admin interface. The interface is enabled by default.

.. _settings-extend-installed-apps:

EXTEND_INSTALLED_APPS
   Default: ``[]``

   Append Django applications to `INSTALLED_APPS
   <https://docs.djangoproject.com/en/dev/ref/settings/#std-setting-INSTALLED_APPS>`_.

   This setting is extended if given in multiple configuration sources, see
   `EXTEND_* settings <settings-extend-settings>`_ for more information.

   If this setting is an environment variable, it must be a JSON-encoded list:

   .. code-block:: bash

      DJANGO_CA_EXTEND_INSTALLED_APPS='["myapp", "otherapp.apps.OtherAppConfig"]'

.. _settings-extend-url-patterns:

EXTEND_URL_PATTERNS
   Default: ``[]``

   Append URL patterns to the default :doc:`URL configuration <django:ref/urls>`. This allows you to add
   custom endpoints to your project.

   This setting is extended if given in multiple configuration sources, see
   `EXTEND_* settings <settings-extend-settings>`_ for more information.

   The syntax is very similar to normal URL configuration. For example:

   .. tab:: Python

      .. literalinclude:: include/config/setting_extend_url_patterns.py
         :language: python

   .. tab:: YAML

      .. literalinclude:: include/config/setting_extend_url_patterns.yaml
         :language: yaml

   If this setting is an environment variable, it must be a JSON-encoded list.

.. _settings-log-format:

LOG_FORMAT
   Default: ``"[%(levelname)-8s %(asctime).19s] %(message)s""``

   The default log format of log messages.  This setting has no effect if you define the ``LOGGING`` setting.

.. _settings-log-level:

LOG_LEVEL
   Default: ``"WARNING"``

   The log level for all messages from **django-ca**. This setting has no effect if you define the ``LOGGING``
   setting.

.. _settings-library-log-level:

LIBRARY_LOG_LEVEL
   Default: ``"WARNING"``

   The log level for all messages _except_ from **django-ca**.  This setting has no effect if you define the
   ``LOGGING`` setting.

.. _settings-secret-key-file:

SECRET_KEY_FILE
   Default: ``"/var/lib/django-ca/secret_key"``

   A path to a file that stores Django's `SECRET_KEY
   <https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-SECRET_KEY>`_. The setting is only used if
   no ``SECRET_KEY`` is defined.

   If you use Docker/docker-compose, the file is automatically generated with a random value on first startup.
   You only have to use this setting if you want to specify a custom value for some reason. If you use
   docker-compose, you should make sure that ``frontend`` and ``backend`` container have access to the same
   file.

.. _settings-global-environment-variables:

****************************
Global environment variables
****************************

If you use the full django-ca project (e.g. if you :doc:`install from source </quickstart/from_source>` or use
:doc:`Docker </quickstart/docker>` or :doc:`docker-compose </quickstart/docker_compose>`), you can also make
use of some environment variables set by other systems.

Configuration directory
=======================

The django-ca project reads custom settings from YAML files in a directory.

All installation options already include a good default for this environment variable and examples in the
quickstart guides assume it is not modified. It is documented here for completeness.

.. _settings-django-ca-settings:

DJANGO_CA_SETTINGS
   The directory where to load YAML settings files. All files in the directory that have a ``.yaml`` suffix
   will be read in alphabetical order.

   Multiple directories can be separated by a colon (``":"``). In this case, django-ca will first read all
   directories from the first directory, then from the second one, and so on.

   The setting can also point to a single file, assumed to be a YAML file.

   If not set, the value of the ``CONFIGURATION_DIRECTORY`` environment variable (see
   :ref:`settings-global-environment-variables-systemd`) is used as a fallback.

.. _settings-env-django-settings:

Django settings
===============

Some standard Django settings (see the :doc:`settings reference <django:ref/settings>`) can also be set via
environment variables. Variables have to be prefixed with ``DJANGO_CA_``, so e.g. the ``SECRET_KEY`` setting
has to use the ``DJANGO_CA_SECRET_KEY`` environment variable.

The ``USE_TZ`` setting is parsed as an |int|, while ``ALLOWED_HOSTS``, ``CACHES``, ``DATABASES``
and ``STORAGES`` are parsed as |dict|. Any standard string setting (such as ``EMAIL_BACKEND`` or
``EMAIL_HOST``) will just work.

Celery settings
===============

If ``CELERY_BEAT_SCHEDULE`` is set as environment variable, it will be parsed as |dict|. Note that it is not
possible to parse a crontab entry that way.

.. _settings-django-ca-startup:

Startup (Docker only)
=====================

The startup scripts in the Docker container read environment variables that influence the startup behavior.

By default, all ``manage.py`` commands are run on startup, but the :doc:`Compose setup
</quickstart/docker_compose>` disables them on some containers to optimize startup times and ensure that they
are only run once.

DJANGO_CA_STARTUP_CACHE_CRLS
    Set to ``0`` if you don't want to run :command:`manage.py cache_crls` on startup.

DJANGO_CA_STARTUP_CHECK
    Set to ``0`` if you don't want to run :command:`manage.py check` (see Djangos :doc:`django:ref/checks`)
    on startup. This will save a second or two in container startup time.

DJANGO_CA_STARTUP_COLLECTSTATIC
    Set to ``0`` if you don't want to run :command:`manage.py collectstatic` on startup.

DJANGO_CA_STARTUP_MIGRATE
    Set to ``0`` if you don't want to run :command:`manage.py migrate` on startup.

DJANGO_CA_STARTUP_REGENERATE_OCSP_KEYS
    Set to ``0`` if you don't want to run :command:`manage.py regenerate_ocsp_keys` on startup.

DJANGO_CA_STARTUP_WAIT_FOR_CONNECTIONS
    A space-separated string in the form of ``hostname:port``, for example ``db.example.com:5432``. If set,
    the startup script will make a TCP connection attempt until the connection succeeds. This can be useful to
    ensure that the main application does not start unless other systems are running.

    This is useful if the startup script is configured to run other ``manage.py`` commands that require access
    to the database. Note that the :doc:`Compose setup </quickstart/docker_compose>` already asserts that via
    healthcheck commands.

DJANGO_CA_STARTUP_WAIT_FOR_SECRET_KEY_FILE
    Set to ``1`` to wait for the secret key file to be created elsewhere. This is used in the Compose setup to
    ensure that one container generates and writes a secret key to a file and the other containers then read
    that file.

.. _settings-django-ca-databases:

Databases
=========

Both the `PostgreSQL <https://hub.docker.com/_/postgres>`_ and `MySQL <https://hub.docker.com/_/mysql>`_
Docker containers get their database name and access credentials from environment variables and **django-ca**
also recognizes these variables.

This is especially powerful when using docker-compose, where it is sufficient to set the ``POSTGRES_PASSWORD``
environment variable to configure the database, all other options use default values that just work.

But any other setup can also make use of this feature. For example, with plain Docker, you could just
configure PostgreSQL:

.. literalinclude:: /include/config/setting_databases_example.yaml
   :language: yaml
   :caption: localsettings.yaml

... and then start your docker containers with (not a full example here):

.. code-block:: console

   $ docker run -e POSTGRES_PASSWORD=... postgres
   $ docker run -e POSTGRES_PASSWORD=... mathiasertl/django-ca

POSTGRES_DB, POSTGRES_DB_FILE, POSTGRES_USER, POSTGRES_USER_FILE, POSTGRES_PASSWORD, POSTGRES_PASSWORD_FILE
   Access details to a PostgreSQL database. See the `Docker image documentation
   <https://hub.docker.com/_/postgres>`__ for more information.

MYSQL_DATABASE, MYSQL_DATABASE_FILE, MYSQL_USER, MYSQL_USER_FILE, MYSQL_PASSWORD, MYSQL_PASSWORD_FILE
   Access details to a MySQL database. See the `Docker image documentation <https://hub.docker.com/_/mysql>`__
   for more information.

MARIADB_DATABASE, MARIADB_DATABASE_FILE, MARIADB_USER, MARIADB_USER_FILE, MARIADB_PASSWORD, MARIADB_PASSWORD_FILE
   Access details to a MariaDB database. See the `Docker image documentation
   <https://hub.docker.com/_/mariadb>`__ for more information.

.. _settings-global-environment-variables-nginx:

NGINX
=====

The :file:`compose.yaml` file provided by the project uses environment variables to parameterize the
NGINX configuration. Except for ``NGINX_TEMPLATE``, these environment variables are *not* used by
**django-ca** itself, but only by the NGINX container itself. As usual, you have to set these variables in
your :file:`.env` file, for example:

.. code-block:: bash
   :caption: .env

   # NGINX TLS configuration
   NGINX_TEMPLATE=tls
   NGINX_PRIVATE_KEY=/etc/certs/live/ca.example.com/privkey.pem
   NGINX_PUBLIC_KEY=/etc/certs/live/ca.example.com/fullchain.pem

NGINX_HOST
   Default: value of ``DJANGO_CA_CA_DEFAULT_HOSTNAME``

   The hostname used by the web server. Internally, this is used in the `server_name
   <http://nginx.org/en/docs/http/server_names.html>`_ directive. The default is to use the value of
   ``DJANGO_CA_CA_DEFAULT_HOSTNAME``, so you usually do *not* have to configure this variable.

NGINX_HTTPS_PORT
   Default: ``443``

   The HTTPS port to use for HTTPS connections. This is only used if you use ``NGINX_TEMPLATE=tls``.

NGINX_PORT
   Default: ``80``

   The HTTP port to use for HTTP connections.

NGINX_PRIVATE_KEY
   Path to the TLS private key. This is only used if you use ``NGINX_TEMPLATE=tls``.

NGINX_PUBLIC_KEY
   Path to the TLS public key. This is only used if you use ``NGINX_TEMPLATE=tls``.

NGINX_TEMPLATE
   Default: ``default``

   The configuration template to use. There are currently only two templates provided by **django-ca**:

   * ``default``: The "simple" default configuration, providing all access via plain HTTP.
   * ``tls``: A configuration that includes TLS configuration. It requires that you also set
     ``NGINX_PRIVATE_KEY`` and ``NGINX_PUBLIC_KEY``.

.. _settings-global-environment-variables-systemd:

SystemD
=======

The django-ca project also recognizes some environment variables set by SystemD.

The SystemD services included in our :doc:`quickstart guide </quickstart/from_source>` already set this
variable and further examples assume that you did not modify it. It is documented here for completeness.

CONFIGURATION_DIRECTORY
   If set, django-ca will load YAML configuration files from this directory. The variable is set by the
   `ConfigurationDirectory=
   <https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RuntimeDirectory=>`_ directive.

.. _settings-extend-settings:

*********************
``EXTEND_*`` settings
*********************

Settings that are prefixed with ``EXTEND_`` are used to extend a different setting. If you use the full
django-ca project (e.g. if you :doc:`install from source </quickstart/from_source>`, or use :doc:`Docker
</quickstart/docker>` or :doc:`docker-compose </quickstart/docker_compose>`) and have multiple configuration
sources, the setting will be extended by all instances in this setting.

For example, if you have:

.. code-block:: yaml
   :caption: conf/10-enable-first-app.yaml

   EXTEND_INSTALLED_APPS:
      - first_app

and:

.. code-block:: yaml
   :caption: conf/20-enable-second-app.yaml

   EXTEND_INSTALLED_APPS:
      - second_app

... then both ``first_app`` and ``second_app`` will be added to ``INSTALLED_APPS``.

*************
Setting types
*************

All **django-ca** settings have a specific type. While they directly map to Python types (if you're familiar
with them), there are a few subtleties in YAML and even more so if you use environment variables.

Note that if you use **django-ca** as app and use normal settings in :file:`settings.py`, you can also always
use the YAML/environment-variable equivalents as well. For example, you can also use ``"P45D"`` to configure
an interval.

.. _settings-types-str:

Strings
=======

Strings are straight forward in all configuration formats. For example:

.. pydantic-setting:: CA_DEFAULT_HOSTNAME
    :example: 0

Warning: unquoted strings in YAML
---------------------------------

A file will fail to load if an unquoted string starts with a character that is also used in the YAML syntax,
for example with a ``*`` or a ``[``:

.. code-block:: yaml

    # THIS WILL NOT WORK:
    #SECRET_KEY: [random-string-that-happens-to-start-with-a-bracket
    # But this will (note the added quotes):
    SECRET_KEY: "[random-string-that-happens-to-start-with-a-bracket"

The same applies to strings that happen to be an integer:

.. code-block:: yaml

    # THIS WILL NOT WORK: A CA serial that happens to have only digits in its hex representation:
    #CA_DEFAULT_CA = 1234
    # But this will (note the added quotes):
    CA_DEFAULT_CA = "1234"

.. _settings-types-int:

Integers
========

Integers are straight forward in all configuration formats. For example:

.. pydantic-setting:: CA_DEFAULT_KEY_SIZE
    :example: 0

.. _settings-types-bool:

:spelling:word:`Booleans`
=========================

Boolean settings are straight forward in Python and YAML syntax. For environment variables, Pydantic model
validation is used:

.. pydantic-setting:: CA_ENABLE_ACME
    :example: 0

String values like ``"true"`` and ``"yes"`` are parsed as true, while ``"false"`` and ``"no"`` are parsed as
false. The official `Conversion Table <https://docs.pydantic.dev/latest/concepts/conversion_table/>`_ has a
list of allowed values for ``str`` inputs for ``bool`` values.

.. _settings-types-timedelta:

Intervals (:spelling:word:`Timedeltas`)
=======================================

Intervals (time deltas) are represented as :py:class:`~datetime.timedelta` objects in Python. In YAML and for
environment variables, you have to use the `ISO 8601 <https://en.wikipedia.org/wiki/ISO_8601#Durations>`_
string representation. For example, to set :ref:`CA_DEFAULT_EXPIRES <settings-ca-default-expires>` to 45 days:

.. pydantic-setting:: CA_DEFAULT_EXPIRES
    :example: 0

Integer values also work, but the meaning depends on the setting. An integer value might be considered as
days or seconds, please refer to the respective setting documentation for the exact meaning. This is
equivalent to the above:

.. pydantic-setting:: CA_DEFAULT_EXPIRES
    :example: 1

.. _settings-types-collections:

Lists and dictionaries
======================

For lists and dictionaries, you can use the standard Python and YAML mechanisms for representation. If you,
use an environment variable, it has to be a JSON-encoded string. For a list:

.. pydantic-setting:: CA_NOTIFICATION_DAYS
    :example: 0

And for a dictionary:

.. pydantic-setting:: CA_PASSWORDS
    :example: 0
