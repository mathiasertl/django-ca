Custom settings
===============

You can use any of the settings understood by `Django
<https://docs.djangoproject.com/en/dev/ref/settings/>`_ and **django-ca**
provides some of its own settings.

From Djangos settings, you especially need to configure ``DATABASES``,
``SECRET_KEY``, ``ALLOWED_HOSTS`` and ``STATIC_ROOT``.

All settings used by **django-ca** start with the ``CA_`` prefix. Settings are
also documented at :file:`ca/ca/localsettings.py.example`
(`view on git
<https://github.com/mathiasertl/django-ca/blob/master/ca/ca/localsettings.py.example>`_).


.. _settings-ca-crl-profiles:

CA_CRL_PROFILES
   Default::

      {
          'user': {
              'algorithm': 'SHA512',
              'expires': 86400,
              'scope': 'user',
              'encodings': ['DER', ],
          },
          'ca': {
              'algorithm': 'SHA512',
              'expires': 86400,
              'scope': 'ca',
              'encodings': ['DER', ],
          },
      }

   A set of CRLs to create using automated tasks.

.. _settings-ca-custom-apps:

CA_CUSTOM_APPS
   Default: ``[]``

   This setting is only used when you use **django-ca** as a standalone project to let you add custom apps to
   the project, e.g. to add :doc:`signals`.

   The list gets appended to the standard ``INSTALLED_APPS`` setting. If you need more control, you can always
   override that setting instead.

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

   If set, the default hostname will be used to set generic URLs for the OCSP responder, assuming that
   ``django_ca`` itself is used as OCSP responder. This setting *must not* include the protocol, as OCSP
   always uses HTTP (not HTTPS) and this setting might be used for other values in the future.

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
   Default: ``{}``

   The default subject to use. The keys of this dictionary are the valid fields
   in X509 certificate subjects. Example::

      CA_DEFAULT_SUBJECT = {
         'C': 'AT',
         'ST': 'Vienna',
         'L': 'Vienna',
         'O': 'HTU Wien',
         'OU': 'Fachschaft Informatik',
         'emailAddress': 'user@example.com',
      }

.. _settings-ca-digest-algorithm:

CA_DIGEST_ALGORITHM
   Default: ``"sha512"``

   The default digest algorithm used to sign certificates. You may want to use ``"sha256"`` for older (before
   2010) clients. Note that this setting is also used by the ``init_ca`` command, so if you have any clients
   that do not understand SHA-512 hashes, you should change this beforehand.

.. _settings-ca-dir:

CA_DIR
   Default: ``"files/"``

   Where the root certificate is stored. The default is a ``files`` directory
   in the same location as your ``manage.py`` file.


CA_ENABLE_CLICKJACKING_PROTECTION
   Default: ``True``

   This setting is only used if you use django-ca as a standalone project, e.g. when using it as a Docker
   container.

   Set to ``False`` to disable `Clickjacking protection
   <https://docs.djangoproject.com/en/dev/ref/clickjacking/>`_. The setting influences if the
   ``XFrameOptionsMiddleware`` is added to the list of middlewares.  This setting is useful if the header is
   already set by the web server.

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


ACME settings
-------------

.. WARNING::

   ACME functionality is still in development and far from ready for any production environment. It is
   disabled by default, and you have to set ``CA_ENABLE_ACME=True`` to enable the feature.

.. _settings-acme-enable-acme:

CA_ENABLE_ACME
   Default: ``False``

   Set to ``True`` to enable ACME functionality. If set to ``False`` (the default), all ACME functionality is
   disabled.

.. _settings-acme-max-cert-validity:

CA_ACME_MAX_CERT_VALIDITY
   Default: ``timedelta(days=90)``

   A ``timedelta`` representing the maximum validity time any certificate issued via ACME is valid.

.. _settings-acme-order-validity:

ACME_ORDER_VALIDITY
   Default: ``1``

   Default time a request for a new certificate ("order") remains valid.
