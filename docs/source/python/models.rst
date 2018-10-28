#######################################
``django_ca.models`` - django-ca models
#######################################

Note that both :py:class:`~django_ca.models.CertificateAuthority` and
:py:class:`~django_ca.models.Certificate` inherit from
:py:class:`~django_ca.models.X509CertMixin`, which provides many convenience
methods.

********************
CertificateAuthority
********************

.. autoclass:: django_ca.models.CertificateAuthority
   :members:
   :exclude-members: DoesNotExist, MultipleObjectsReturned

Manager methods
===============

.. autoclass:: django_ca.managers.CertificateAuthorityManager
   :members:


***********
Certificate
***********

.. autoclass:: django_ca.models.Certificate
   :members:
   :exclude-members: DoesNotExist, MultipleObjectsReturned

Manager methods
===============

.. autoclass:: django_ca.managers.CertificateManager
   :members:

*************
X509CertMixin
*************

:py:class:`~django_ca.models.X509CertMixin` is a common base class to both
:py:class:`~django_ca.models.CertificateAuthority` and
:py:class:`~django_ca.models.Certificate` and provides many convenience
attributes.

.. autoclass:: django_ca.models.X509CertMixin
   :members:
