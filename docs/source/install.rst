############
Installation
############

There are multiple ways of installing **django-ca**. Each supported installation method has its own quickstart
guide:

* :doc:`quickstart/docker_compose`: By far the easiest, fastest and most reliable way.
* :doc:`quickstart/as_app`: If you want to integrate django-ca into your existing Django project.
* :doc:`quickstart/from_source`: If you want to install the project from source (or want to use it as a
  template for a totally different platform).
* :doc:`quickstart/docker`: If you already have web server, database etc. set up or as a template for
  orchestration platforms such as Docker Swarm.

.. _http-explanation:

Why plain HTTP?!
================

OCSP and CRL access (protocols used to obtain the revocation status of certificates) usually work via HTTP,
**not** HTTPS. Clients would need to obtain the revocation status of the certificate used for the HTTPS
connection using that same HTTPS connection. Responses are signed, so using HTTP is not considered a security
vulnerability.

Just in case you doubt the above: check how publicly trusted and widely used certificate authorities set the
:ref:`ca-example-crlDistributionPoints` and :ref:`ca-example-AuthorityInfoAccess` extensions.

However, only CRL, OCSP and issuer information needs to be available via HTTP.  If you use ``/ca`` as path in
your URL configuration (like in the example above), you only need ``/ca/issuer/``, ``/ca/ocsp/`` and
``/ca/crl/`` available via HTTP.
