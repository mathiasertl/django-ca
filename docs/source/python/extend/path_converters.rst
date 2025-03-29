###############
Path converters
###############

**django-ca** provides several path converters that you can use in your own URL configurations.

*************
django-ca-hex
*************

A path converter that accepts hex values, possibly with semicolons. It does *not* sanitize the input value in
any way.

This converter is intended for hex-encoded serials in URLs that are retrieved and used programmatically. For
example, the OCSP endpoint is encoded in the certificate itself, and clients will call it without user
interaction. **django-ca** already takes care of sanitizing the URL in the certificate, so it should never
be called with semicolons in the first place.

****************
django-ca-serial
****************

A path converter that accepts hex values, but sanitizes input values by removing semicolons and leading zeros.

The path element can be used to retrieve :py:class:`~django_ca.models.CertificateAuthority` or
:py:class:`~django_ca.models.Certificate` instances from the database.

For example, consider this URL configuration:

.. code-block:: python
   :caption: :file:`urls.py`

   from django.urls import path

   from . import my_views

   urlpatterns = [
       path("<django-ca-serial:serial>/", my_views.MyView.as_view())
   ]

Your view implementation can then use the serial to fetch data from the database:

.. literalinclude:: /include/extend/path_converters_serial_view.py
   :caption: file:`views.py`
   :language: python

****************
django-ca-base64
****************

A path converter that accepts characters for base64-encoded values. Note that this converter does *not*
decode data, as endpoints might need to return custom error responses in case of malformed data.

*******************
django-ca-acme-slug
*******************

A converter that accepts ACME slugs. This is used internally for the ACME implementation.

