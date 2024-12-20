####################
Deprecation timeline
####################

***********
2.3.0 (TBR)
***********

Dependencies
============

* Remove support for django 5.0.

Command-line
============

* The ``--scope`` and ``--algorithm`` parameters to :command:`manage.py dump_crl` will be removed (deprecated
  since django-ca 2.1.0).

Settings
========

* The `scope` and `encodings` parameter to :ref:`settings-ca-crl-profiles` will be removed (deprecated since
  django-ca 2.1.0).

Python API
==========

* The `expires` parameter to functions that create a certificate will be removed. Use `not_after` instead
  (deprecated since 2.1.0). The following functions are affected:

  * :func:`django_ca.models.CertificateAuthority.sign`
  * :func:`django_ca.models.CertificateAuthority.generate_ocsp_key`
  * :func:`django_ca.managers.CertificateAuthorityManager.init`
  * :func:`django_ca.managers.CertificateManager.create_cert`
  * :func:`django_ca.profiles.Profile.create_cert`

* The `scope` parameter to :func:`~django_ca.utils.get_crl_cache_key` will be removed (deprecated since
  django-ca 2.1.0).
* :func:`django_ca.models.CertificateAuthority.get_crl_certs` and
  :func:`django_ca.models.CertificateAuthority.get_crl` will be removed (deprecated since django-ca 2.1.0).

Views
=====

* The `scope` and `include_issuing_distribution_point` :class:`~django_ca.views.CertificateRevocationListView`
  parameters will be removed (deprecated since 2.1.0).

***********
2.2.0 (TBR)
***********

Command-line
============

* Remove support for subjects in OpenSSL-style format (default switched in 2.0.0, deprecated since 1.27.0).

Settings
========

* Support for the old subject format in :ref:`settings-ca-default-subject` and subjects in profiles will be
  removed in 2.2.0 (deprecated since 1.29.0).

Python API
==========

* ``django_ca.utils.get_storage()`` will be removed (deprecated since 2.0).

Dependencies
============

* Support ``django~=5.0.0`` will be dropped.

***********
2.1.0 (TBR)
***********

Views
=====

* Configuring a password in a certificate revocation list view will be removed. Use the ``CA_PASSWORDS``
  setting instead (deprecated since 1.29.0).

Dependencies
============

* Support ``pydantic~=2.7.0``, ``pydantic~=2.8.0``, ``cryptography~=42.0`` and ``acme~=2.10.0`` will be
  dropped.
