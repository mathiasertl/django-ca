###############
Custom settings
###############

You can use any of the settings understood by `Django <https://docs.djangoproject.com/en/dev/ref/settings/>`_
and **django-ca** provides some of its own settings.

****************
How to configure
****************

If you use django-ca :doc:`as a Django app </quickstart_as_app>`, set settings normally using your
:file:`settings.py` file (or whatever custom mechanism you have devised).

If you use the full django-ca project (e.g. if you :doc:`install from source </quickstart_from_source>`, or
use :doc:`Docker </docker>` or :doc:`docker-compose </quickstart_docker_compose>`), do *not* update the
:file:`settings.py` file included with django-ca. Instead, use `YAML <https://en.wikipedia.org/wiki/YAML>`_
files that django-ca loads (in alphabetical order) from a preconfigured directory. Please see the respective
installation instructions for how to override settings, and see :ref:`settings-yaml-configuration` for format
instructions.

The django-ca project also lets you override simple string-like settings via environment variables. The
environment variable name is the same as the setting but prefixed with ``DJANGO_CA_``. For example to set the
``CA_DIR`` setting, pass a ``DJANGO_CA_CA_DIR`` environment variable. Environment variables take precedence
over the YAML configuration files above.

The django-ca project also recognizes some environment variables to better integrate with other systems. See
:ref:`settings-global-environment-variables` for more information.

************************
Required Django settings
************************

If you use django-ca :doc:`as a Django app </quickstart_as_app>` the only required settings are the settings
any Django project requires anyway, most importantly ``DATABASES``, ``SECRET_KEY``, ``ALLOWED_HOSTS`` and
``STATIC_ROOT``.

If you :doc:`install from source </quickstart_from_source>`, you only have to set the ``DATABASES`` and
``SECRET_KEY`` settings. The ``CA_DEFAULT_HOSTNAME`` also configures the ``ALLOWED_HOSTS`` setting if not set
otherwise. Please see the `section on configuration <from-source-configuration>`_ for more information.

If you use :doc:`Docker </docker>` or :doc:`docker-compose </quickstart_docker_compose>`, there isn't really
any standard Django setting you need to configure, as safe defaults are used. A safe value for ``SECRETS_KEY``
is generated automatically, ``ALLOWED_HOSTS`` is set via ``CA_DEFAULT_HOSTNAME`` and the ``DATABASES`` setting
is automatically populated with environment variables also used by the PostgreSQL/MySQL containers.

******************
django-ca settings
******************

All settings used by **django-ca** start with the ``CA_`` prefix.

.. _settings-ca-crl-profiles:

CA_CRL_PROFILES
   Default::

      {
          'user': {
              'algorithm': 'SHA512',
              'expires': 86400,
              'scope': 'user',
              'encodings': ["DER", "PEM"],
          },
          'ca': {
              'algorithm': 'SHA512',
              'expires': 86400,
              'scope': 'ca',
              'encodings': ["DER", "PEM"],
          },
      }

   A set of CRLs to create using automated tasks. The default value is usually fine.

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

   Note that the hash algorithm will default to ``"SHA256"`` for certificate authorities with DSA keys, unless
   you specify a different value in the ``"OVERRIDES"`` value described above.

.. _settings-ca-default-ca:

CA_DEFAULT_CA
   Default: ``""``

   The serial of the CA to use when no CA is explicitly given.

   For example, if you sign a certificate using the :ref:`manage.py sign_cert <cli_sign_certs>` command and do
   not pass the ``--ca`` parameter, the CA given here will be used. You can get a list of serials from the
   admin interface or via the ``manage.py list_cas`` command.

   .. WARNING::

      Some parts of **django-ca** will start throwing errors when attempting to use a default CA that is
      expired or disabled. So please make sure you keep this setting up to date.

   If this setting is *not* set, **django-ca** will select the CA that is currently usable (enabled, currently
   valid, not revoked) and and has an expiry furthest in the future.

.. _settings-ca-default-ecc-curve:

CA_DEFAULT_ECC_CURVE
   Default: ``"SECP256R1"``

   The default elliptic curve used for generating CA private keys when ECC is used.

.. _settings-ca-default-expires:

CA_DEFAULT_EXPIRES
   Default: ``730``

   The default time, in days, that any signed certificate expires.

.. _settings-ca-default-hostname:

CA_DEFAULT_HOSTNAME
   Default: ``None``

   If set, the default hostname will be used to automatically generate URLs for CRLs and OCSP services.  This
   setting *must not* include the protocol, as OCSP always uses HTTP (not HTTPS) and this setting might be
   used for other values in the future.

   .. WARNING::

      If you change this setting, CRLs configured to contain only CA revocation information (that is, to check
      if an intermediate CA *itself* was revoked) are no longer strictly valid. However, few if any
      implementations actually implement validation for this.

      If you change this setting, you should configure django-ca to continue using the old URLs.

   Example value: ``"ca.example.com"``.

.. _settings-ca-default-key-size:

CA_DEFAULT_KEY_SIZE
   Default: ``4096``

   The default key size for newly created CAs (not used for CAs based on ECC).

.. _settings-ca-default-profile:

CA_DEFAULT_PROFILE
   Default: ``webserver``

   The default profile to use.

.. _settings-ca-default-subject:

CA_DEFAULT_SUBJECT
   Default: ``tuple()`` (empty tuple)

   The default subject to use. The keys of this dictionary are the valid fields in X509 certificate subjects.
   Example::

      CA_DEFAULT_SUBJECT = (
         ("C", "AT"),
         ("ST", "Vienna"),
         ("L", "Vienna"),
         ("O", "Example"),
         ("OU", "Example Unit"),
         ("emailAddress", "user@example.com"),
      )

.. _settings-ca-digest-algorithm:

CA_DIGEST_ALGORITHM
   Default: ``"sha512"``

   The default digest algorithm used to sign certificates.  Note that this setting is also used by the
   ``init_ca`` command, so if you have any clients that do not understand SHA-512 hashes, you should change
   this beforehand.

.. _settings-ca-dir:

CA_DIR
   Default: ``"files/"``

   Where the root certificate is stored. The default is a ``files`` directory in the same location as your
   ``manage.py`` file.

.. _settings-ca-file-storage:

CA_FILE_STORAGE
   Default: ``'django.core.files.storage.FileSystemStorage'``

   Default storage backend for files created by django-ca. The default is the same as *the default* for
   ``DEFAULT_FILE_STORAGE``, so django-ca will still use local file system storage even if you configure a
   different storage backend in ``DEFAULT_FILE_STORAGE``. The default uses :ref:`CA_FILE_STORAGE_KWARGS
   <settings-ca-file-storage-kwargs>` to store files in a different location, since the default
   (``MEDIA_ROOT``) is commonly used to upload user-generated files that are exposed to the web by the
   web server.

.. _settings-ca-file-storage-kwargs:

CA_FILE_STORAGE_KWARGS
   Default: ``{'location': 'files/', 'file_permissions_mode': 0o600, 'directory_permissions_mode': 0o700}``

   Add any arguments to the storage backend configured in :ref:`CA_FILE_STORAGE <settings-ca-file-storage>`.

CA_NOTIFICATION_DAYS
   Default: ``[14, 7, 3, 1, ]``

   Days before expiry that certificate watchers will receive notifications. By default, watchers
   will receive notifications 14, seven, three and one days before expiry.

.. _settings-ca-ocsp-urls:

CA_OCSP_URLS
   Default: ``{}``

   Configuration for OCSP responders. See :doc:`ocsp` for more information.

.. _settings-ca-passwords:

CA_PASSWORDS
   Default: ``{}``

   A dictionary configuring passwords for the private keys of CAs. This setting is required if you create a CA
   with an encrypted private key and want to automatically create CRLs and OCSP keys.

.. _settings-ca-profiles:

CA_PROFILES
   Default: ``{}``

   Add new profiles or change existing ones.  Please see :doc:`profiles` for more information on profiles.

.. _settings-ca-use-celery:

CA_USE_CELERY
   Default: ``None``

   Set to ``True`` to force django-ca to use `Celery <https://docs.celeryproject.org>`_ or to ``False`` to
   force not using it. The default is to use Celery if it is installed.

.. _settings-acme:

ACMEv2 settings
===============

.. _settings-acme-enable-acme:

CA_ENABLE_ACME
   Default: ``True``

   Set to ``False`` to disable all ACME functionality.

   Note that even when enabled, you need to explicitly enable ACMEv2 support for a certificate authority
   either via the admin interface or via :doc:`the command-line interface </cli/cas>`.

CA_ACME_ACCOUNT_REQUIRES_CONTACT
   Default: ``True``

   Set to false to allow creating ACMEv2 accounts without an email address.

CA_ACME_DEFAULT_CERT_VALIDITY
   Default: ``timedelta(days=90)``

   A ``timedelta`` representing the default validity time any certificate issued via ACME is valid.

.. _settings-acme-max-cert-validity:

CA_ACME_MAX_CERT_VALIDITY
   Default: ``timedelta(days=90)``

   A ``timedelta`` representing the maximum validity time any certificate issued via ACME is valid. The ACMEv2
   protocol allows for clients to request a non-default validity time, but certbot currently does not expose
   this feature.

.. _settings-acme-order-validity:

CA_ACME_ORDER_VALIDITY
   Default: ``1``

   Default time (in hours) a request for a new certificate ("order") remains valid. You may also set
   a ``timedelta`` object.

****************
Project settings
****************

Project settings are available if you use the full **django-ca** project (including if you use the Docker
container or via docker-compose). The settings are _not_ prefixed with ``CA_``, because they configure how
Django itself works.

As any other setting, they can be set by using environment variables prefixed with ``DJANGO_CA_`` (Example: To
set ``LOG_LEVEL``, set the ``DJANGO_CA_LOG_LEVEL`` environment variable).

.. _settings-ca-custom-apps:

CA_CUSTOM_APPS
   Default: ``[]``

   The list gets appended to the standard ``INSTALLED_APPS`` setting. If you need more control, you can always
   override that setting instead.

CA_ENABLE_CLICKJACKING_PROTECTION
   Default: ``True``

   Set to ``False`` to disable `Clickjacking protection
   <https://docs.djangoproject.com/en/dev/ref/clickjacking/>`_. The setting influences if the
   ``XFrameOptionsMiddleware`` is added to the list of middlewares.  This setting is useful if the header is
   already set by the web server.

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

   A path to a file that stores Djangos `SECRET_KEY
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

If you use the full django-ca project (e.g. if you :doc:`install from source </quickstart_from_source>` or use
:doc:`Docker </docker>` or :doc:`docker-compose </quickstart_docker_compose>`), you can also make use of some
environment variables set by other systems.

Configuration directory
=======================

The django-ca project reads custom settings from YAML files in a directory.

All installation options already include a good default for this environment variable and examples in the
quickstart guides assume it is not modified. It is documented here for completeness.

DJANGO_CA_SETTINGS
   The directory where to load YAML settings files. All files in the directory that have a ``.yaml`` suffix
   will be read in alphabetical order.

   Multiple directories can be separated by a colon (``":"``). In this case, django-ca will first read all
   directories from the first directory, then from the second one, and so on.

   The setting can also point to a single file, assumed to be a YAML file.

   If not set, the value of the ``CONFIGURATION_DIRECTORY`` environment variable (see
   :ref:`settings-global-environment-variables-systemd`) is used as a fallback.


Databases
=========

Both the `PostgreSQL <https://hub.docker.com/_/postgres>`_ and `MySQL <https://hub.docker.com/_/mysql>`_
Docker containers get their database name and access credentials from environment variables and **django-ca**
also recognizes these variables.

This is especially powerful when using docker-compose, where it is sufficient to set the ``POSTGRES_PASSWORD``
environment variable to configure the database, all other options use default values that just work.

But any other setup can also make use of this feature. For example, with plain Docker, you could just
configure PostgreSQL:

.. code-block:: yaml
   :caption: localsettings.yaml

   DATABASES:
      default:
         ENGINE: django.db.backends.postgresql_psycopg2

... and then start your docker containers with (not a full example here):

.. code-block:: console

   $ docker run -e POSTGRES_PASSWORD=... postgres
   $ docker run -e POSTGRES_PASSWORD=... mathiasertl/django-ca

POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
   Access details to a PostgreSQL database.

MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD
   Access details to a MySQL database.

.. _settings-global-environment-variables-systemd:

SystemD
=======

The django-ca project also recognizes some environment variables set by SystemD.

The SystemD services included in our :doc:`quickstart guide <quickstart_from_source>` already set this
variable and further examples assume that you did not modify it. It is documented here for completeness.

CONFIGURATION_DIRECTORY
   If set, django-ca will load YAML configuration files from this directory. The variable is set by the
   `ConfigurationDirectory=
   <https://www.freedesktop.org/software/systemd/man/systemd.exec.html#RuntimeDirectory=>`_ directive.

.. _settings-yaml-configuration:

******************
YAML configuration
******************

The Django project you use if you :doc:`install from source </quickstart_from_source>`, use :doc:`Docker
</docker>` or :doc:`docker-compose </quickstart_docker_compose>` loads YAML files from a directory. This
enables you to configure django-ca with a normal configuration file format without having to know Python.

.. seealso:: https://en.wikipedia.org/wiki/YAML - Wikipedia has an overview of the YAML syntax.

The individual tutorials give detailed instructions on where you can place these configurations files, this
section documents how to translate Python settings described above into YAML.

* The file must be a key/value mapping at the top level (as all examples are).
* Boolean, string and integer values can be used in standard YAML syntax.
* List or tuple values both map to YAML lists.
* Dictionaries map to YAML dictionaries.

Warning: unquoted strings
=========================

A file will fail to load if an unquoted string starts with a character that is also used in the YAML syntax,
for example with a ``*`` or a ``[``. This is invalid YAML:

.. code-block:: yaml

   # THIS WILL NOT WORK:
   SECRET_KEY: [random-string-that-happens-to-start-with-a-bracket

Strings must also be quoted if they contain only digits (or resemble a different YAML data type), as they
would otherwise be loaded as the respective data type:

.. code-block:: yaml

   # WRONG: serial that happens to have only digits would be loaded as integer
   CA_DEFAULT_CA: 12345

In both cases, the solution is to quote the string:

.. code-block:: yaml

   SECRET_KEY: "[random-string-that-happens-to-start-with-a-bracket"
   CA_DEFAULT_CA: "12345"

Examples
========

Basic settings are straight forward:

.. literalinclude:: include/yaml-example-basic.yaml
   :language: yaml


Nested mappings such as the ``DATABASES`` are of course also possible:

.. literalinclude:: include/yaml-example-databases.yaml
   :language: yaml

Settings that are tuples like `CA_DEFAULT_SUBJECT <settings-ca-default-subject>`_ have to be defined as lists:

.. literalinclude:: include/yaml-example-subject.yaml
   :language: yaml

The `CA_PROFILES <settings-ca-profiles>`_ setting can also be set using YAML. Here is a verbose example:

.. literalinclude:: include/yaml-example-ca-profiles.yaml
   :language: yaml
