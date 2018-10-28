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

:py:class:`~django_ca.managers.CertificateAuthorityManager` is the default manager for
:py:class:`~django_ca.models.CertificateAuthority`, meaning you can access it
using ``CertificateAuthority.objects``, e.g.::

   >>> from django_ca.models import CertificateAuthority
   >>> CertificateAuthority.objects.init(...)

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

:py:class:`~django_ca.managers.CertificateManager` is the default manager for
:py:class:`~django_ca.models.Certificate`, meaning you can access it
using ``Certificate.objects``, e.g.::

   >>> from django_ca.models import Certificate
   >>> Certificate.objects.init(...)

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
