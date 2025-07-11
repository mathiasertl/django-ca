###########
2.3.0 (TBR)
###########

* Add support for the `PrivateKeyUsagePeriod` extension. Support requires that you use ``cryptography>=45``.
* Regenerate CRL in view if newest CRL is expired (fixes (`#167
  <https://github.com/mathiasertl/django-ca/issues/167>`_).

********
Database
********

* Update models to fully support MySQL and MariaDB.
* Squash migrations for a faster setup process. Old migrations will be removed in ``django-ca~=2.5.0``.

********
Settings
********

* CA_CRL_PROFILES: The ``scope`` parameter was removed (deprecated since 2.1.0). Use ``only_contains_*``
  parameters instead.
* CA_CRL_PROFILES: The ``encoding`` parameter was removed (deprecated since 2.1.0). All encodings are now
  always available.
* Add support for ``MARIADB_*`` environment variables to configure MariaDB when using django-ca as a project.
  See :ref:`settings-django-ca-databases` for more information.
* When using the django-ca Docker container, allow configuration of which ``manage.py`` commands are run on
  startup. See :ref:`settings-django-ca-startup` for more information.

************
Command-line
************

* The ``--scope`` and ``--algorithm`` parameters to :command:`manage.py dump_crl` where removed (deprecated
  since django-ca 2.1.0).
* :command:`manage.py resign_cert`:

  * Overriding details from the original certificate is deprecated and will be removed in
    ``django-ca~=2.4.0``. This affects ``--ca``, ``--subject``, ``--profile``, ``--algorithm``,
    ``--ocsp-responder``, ``--ca-issuer``, ``--policy-identifier``, ``--certification-practice-statement``,
    ``--user-notice``, ``--crl-full-name``, ``--issuer-alternative-name``, ``--extended-key-usage``,
    ``--key-usage``, ``--ocsp-no-check``, ``--subject-alternative-name`` and ``--tls-feature``, as well as all
    arguments to mark them as (not) critical. These arguments make the behavior unpredictable and make it hard
    to predict what the certificate really looks like. If you want to sign a certificate again with different
    extensions, sign the certificate normally. It will still be possible to resign a certificate using a
    different CA.

* :command:`manage.py regenerate_ocsp_keys`:

  * Deprecate the ``--profile`` and ``--expires`` arguments. The arguments will be removed in
    ``django-ca~=2.4.0``. The profile should always be "ocsp", which can also influence certificate expiry.
  * Deprecate the ``--key-type``, ``--key-size``, ``--elliptic-curve`` and ``--algorithm`` arguments. The
    arguments will be removed in ``django-ca~=2.4.0``. OCSP keys generated with this command then mirror the
    CA they are delegating for.
  * No longer require the private key to be usable where the command is invoked if Celery is used.
  * Remove default value for ``--expires``, which masks the configured CA value.

********
REST API
********

* Add ability to resign certificates via the API (fixes
  `#155 <https://github.com/mathiasertl/django-ca/issues/155>`_).
* Add CSR when signing certificates (fixes `#163 <https://github.com/mathiasertl/django-ca/issues/163>`_).
* The URL path for the revocation endpoint has changed. It is now
  ``/ca/{ca_serial}/certs/{certificate_serial}/revoke/`` instead of
  ``/ca/{ca_serial}/revoke/{certificate_serial}/``. The old API endpoint will be removed in
  ``django-ca~=2.5.0``.

************
Dependencies
************

* Add support for ``django~=5.2.0``, ``Celery~=5.5.0``, ``pydantic~=2.11.0``, ``acme~=3.3.0`` and
  ``acme~=4.0.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for ``django~=4.2.0``, ``acme~=3.0.0`` and ``acme~=3.1.0``.
* **BACKWARDS INCOMPATIBLE:** Dropped support for Alpine 3.19.

**********
Python API
**********

* The `expires` parameter to functions that create a certificate was removed. Use `not_after` instead
  (deprecated since 2.1.0). The following functions are affected:

  * :func:`django_ca.models.CertificateAuthority.sign`
  * :func:`django_ca.models.CertificateAuthority.generate_ocsp_key`
  * :func:`django_ca.managers.CertificateAuthorityManager.init`
  * :func:`django_ca.managers.CertificateManager.create_cert`
  * :func:`django_ca.profiles.Profile.create_cert`

* ``django_ca.extensions.parse_extension()`` was removed (deprecated since ``django-ca==2.2.0``). Use
  :doc:`Pydantic models </python/pydantic>` instead.
* ``django_ca.models.CertificateAuthority.get_crl_certs()`` and
  ``django_ca.models.CertificateAuthority.get_crl()`` where removed (deprecated since django-ca 2.1.0).
* Functions related to the old OpenSSL style subject format will be removed in (deprecated since
  ``django_ca==2.2.0``):

  * ``django_ca.utils.parse_name_x509()``
  * ``django_ca.utils.parse_serialized_name_attributes()``
  * ``django_ca.utils.serialize_name()``
  * ``django_ca.utils.split_str()``
  * ``django_ca.utils.x509_name()``

*******************
Deprecation notices
*******************

* This is the last release to support ``Celery~=4.4.0``.
* This is the last release to support ``acme~=3.2.0`` and ``acme~=3.3.0``.

*****
Views
*****

* The `scope` and `include_issuing_distribution_point` :class:`~django_ca.views.CertificateRevocationListView`
  parameters where be removed (deprecated since 2.1.0).
