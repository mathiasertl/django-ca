Custom settings
===============

You can use any of the settings understood by `Django
<https://docs.djangoproject.com/en/dev/ref/settings/>` and **django-ca**
provides some of its own settings.

From Djangos settings, you especially need to configure ``DATABASES``,
``SECRET_KEY``, ``ALLOWED_HOSTS`` and ``STATIC_ROOT``.

All settings used by **django-ca** start with the ``CA_`` prefix. Settings are
also documented at :file:`ca/ca/localsettings.py.example`
(`view on git
<https://github.com/mathiasertl/django-ca/blob/master/ca/ca/localsettings.py.example>`_).

CA_ALLOW_CA_CERTIFICATES
   Default: ``False``

CA_CRL_DISTRIBUTION_POINTS
   Default: ``[]``

CA_CUSTOM_PROFILES
   Default: ``{}``

CA_DEFAULT_EXPIRES
   Default: ``720``

CA_DEFAULT_PROFILE
   Default: ``webserver``

CA_DIGEST_ALGORITHM
   Default: ``"sha512"``

CA_DIR
   Default: ``"ca/files"``

CA_ISSUER
   Default: ``None``

CA_ISSUER_ALT_NAME
   Default: ``None``

CA_OCSP
   Default: ``None``

CA_PROFILES
   Default:
