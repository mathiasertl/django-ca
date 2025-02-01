####################
Deprecation timeline
####################

***********
2.5.0 (TBR)
***********

* The ``CA_CUSTOM_APPS`` setting will be removed. Use

***********
2.3.0 (TBR)
***********

Dependencies
============

* Drop support for Python 3.9 and ``django~=4.2.0``

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
* ``django_ca.extensions.parse_extension()`` is deprecated and will be removed (deprecated since
  ``django-ca==2.2.0``). Use :doc:`Pydantic models </python/pydantic>` instead.
* Functions related to the old OpenSSL style subject format will be removed in (deprecated since
  ``django_ca==2.2.0``):

  * ``django_ca.utils.parse_name_x509()``
  * ``django_ca.utils.parse_serialized_name_attributes()``
  * ``django_ca.utils.serialize_name()``
  * ``django_ca.utils.split_str()``
  * ``django_ca.utils.x509_name()``

Views
=====

* The `scope` and `include_issuing_distribution_point` :class:`~django_ca.views.CertificateRevocationListView`
  parameters will be removed (deprecated since 2.1.0).
