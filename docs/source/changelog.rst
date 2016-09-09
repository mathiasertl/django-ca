#########
ChangeLog
#########

.. _changelog-head:

****
HEAD
****

* Make sure that Child CAs never expire after their parents. If the user specifies an expiry after
  that of the parent, it is silently changed to the parents expiry.
* Make sure that certificates never expire after their CAs. If the user specifies an expiry after
  that of the parent, throw an error.
* Improve help-output of ``--init-ca`` and ``--sign-cert`` by further grouping arguments into
  argument groups.
* Add ability to add CRL-, OCSP- and Issuer-URLs when creating CAs using the ``--ca-*`` options.
* Add support for the ``nameConstraints`` X509 extension when creating CAs. The option to the
  ``init_ca`` command is ``--name-constraint`` and can be given multiple times to indicate multiple
  constraints.
* Add support for the ``tlsfeature`` extension, a.k.a. "TLS Must Staple". Since OpenSSL 1.1 is
  required for this extension, support is currently totally untested.

.. _changelog-1.3.0:

******************
1.3.0 (2016-07-09)
******************

* Add links for downloading the certificate in PEM/ASN format in the admin interface.
* Add an extra chapter in documentation on how to create intermediate CAs.
* Correctly set the issuer field when generating intermediate CAs.
* ``fab init_demo`` now actually creates an intermediate CA.
* Fix help text for the ``--parent`` parameter for ``manage.py init_ca``.

.. _changelog-1.2.2:

******************
1.2.2 (2016-06-30)
******************

* Rebuild to remove old migrations accidentally present in previous release.

.. _changelog-1.2.1:

******************
1.2.1 (2016-06-06)
******************

* Add the ``CA_NOTIFICATION_DAYS`` setting so that watchers don't receive too many emails.
* Fix changing a certificate in the admin interface (only watchers can be changed at present).

.. _changelog-1.2.0:

******************
1.2.0 (2016-06-05)
******************

* **django-ca** now provides a complete :doc:`OCSP responder <ocsp>`.
* Various tests are now run with a pre-computed CA, making tests much fater and output more
  predictable.
* Update lots of documentation.

.. _changelog-1.1.1:

******************
1.1.1 (2016-06-05)
******************

* Fix the ``fab init_demo`` command.
* Fix installation via ``setup.py install``, fixes
  `#2 <https://github.com/mathiasertl/django-ca/issues/2>`_ and `#4
  <https://github.com/mathiasertl/django-ca/issues/4>`_.  Thanks to Jon McKenzie for the fixes!

.. _changelog-1.1.0:

******************
1.1.0 (2016-05-08)
******************

* The subject given in the ``manage.py init_ca`` and ``manage.py sign_cert`` is now given in the
  same form that is frequently used by OpenSSL, "/C=AT/L=...".
* On the command line, both CAs and certificates can now be named either by their CommonName or
  with their serial. The serial can be given with only the first few letters as long as it's
  unique, as it is matched as long as the serial starts with the given serial.
* Expiry time of CRLs can now be specified in seconds. ``manage.py dump_crl`` now uses the
  ``--expires`` instead of the old ``--days`` parameter.
* The admin interface now accounts for cases where some or all CAs are not useable because the
  private key is not accessable. Such a scenario might occur if the private keys are hosted on a
  different machine.
* The app now provides a generic view to generate CRLs. See :ref:`crl-generic` for more information.
* Fix the display of the default value of the --ca args.
* Move this ChangeLog from a top-level .md file to this location.
* Fix shell example when issueing certificates.

.. _changelog-1.0.1:

******************
1.0.1 (2016-04-27)
******************

* Officially support Python2.7 again.
* Make sure that certificate authorities cannot be removed via the web interface.

.. _changelog-1.0.0:

******************
1.0.0 (2016-04-27)
******************

This represents a massive new release (hence the big version jump). The project
now has a new name (**django-ca** instead of just "certificate authority") and
is now installable via pip. Since versions prior to this release probably had no users (as it
wasn't advertised anywhere), it includes several incompatible changes.

General
=======

* This project now runs under the name **django-ca** instead of just "certificate authority".
* Move the git repository is now hosted at https://github.com/mathiasertl/django-ca.
* This version now absolutely assumes Python3. Python2 is no longer supported.
* Require Django  1.8 or later.
* django-ca is now usable as a stand-alone project (via git) or as a reusable app (via pip).

Functionality
=============

* The main app was renamed from ``certificate`` to ``django_ca``. See below for how to upgrade.

manage.py interface
===================

* ``manage.py`` commands are now renamed to be more specific:

  * ``init`` -> ``init_ca``
  * ``sign`` -> ``sign_cert``
  * ``list`` -> ``list_certs``
  * ``revoke`` -> ``revoke_cert``
  * ``crl`` -> ``dump_crl``
  * ``view`` -> ``view_cert``
  * ``watch`` -> ``notify_expiring_certs``
  * ``watchers`` -> ``cert_watchers``

* Several new ``manage.py`` commands:

  * ``dump_ca`` to dump CA certificates.
  * ``dump_cert`` to dump certificates to a file.
  * ``dump_ocsp_index`` for an OCSP responder, ``dump_crl`` no longer outputs this file.
  * ``edit_ca`` to edit CA properties from the command line.
  * ``list_cas`` to list available CAs.
  * ``view_ca`` to view a CA.

* Removed the ``manage.py remove`` command.
* ``dump_{ca,cert,crl}`` can now output DER/ASN1 data to stdout.

.. _changelog-0.2.1:

******************
0.2.1 (2015-05-24)
******************

* Signed certificates are valid five minutes in the past to account for possible clock skew.
* Shell-scripts: Correctly pass quoted parameters to manage.py.
* Add documentation on how to test CRLs.
* Improve support for OCSP.

.. _changelog-0.2:

****************
0.2 (2015-02-08)
****************

* The ``watchers`` command now takes a serial, like any other command.
* Reworked ``view`` command for more robustness.

  * Improve output of certificate extensions.
  * Add the ``-n``/``--no-pem`` option.
  * Add the ``-e``/``--extensions`` option to print all certificate extensions.
  * Make output clearer.

* The ``sign`` command now has

  * a ``--key-usage`` option to override the ``keyUsage`` extended attribute.
  * a ``--ext-key-usage`` option to override the ``extendedKeyUsage`` extended attribute.
  * a ``--ocsp`` option to sign a certificate for an OCSP server.

* The default ``extendedKeyUsage`` is now ``serverAuth``, not ``clientAuth``.
* Update the remove command to take a serial.
* Ensure restrictive file permissions when creating a CA.
* Add requirements-dev.txt

.. _changelog-0.1:

****************
0.1 (2015-02-07)
****************

* Initial release
