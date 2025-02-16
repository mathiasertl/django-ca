###########
2.3.0 (TBR)
###########

********
Settings
********

* CA_CRL_PROFILES: The ``scope`` parameter was removed (deprecated since 2.1.0). Use ``only_contains_*``
  parameters instead.
* CA_CRL_PROFILES: The ``encoding`` parameter where removed (deprecated since 2.1.0). All encodings are now
  always available.

************
Command-line
************

* The ``--scope`` and ``--algorithm`` parameters to :command:`manage.py dump_crl` will be removed (deprecated
  since django-ca 2.1.0).

************
Dependencies
************

* **BACKWARDS INCOMPATIBLE:** Dropped support for ``django~=4.2.0``, ``acme~=3.0.0`` and ``acme~=3.`.0``.
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

*****
Views
*****

* The `scope` and `include_issuing_distribution_point` :class:`~django_ca.views.CertificateRevocationListView`
  parameters where be removed (deprecated since 2.1.0).
