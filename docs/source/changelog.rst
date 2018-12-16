#########
ChangeLog
#########

.. _changelog-head:

************
1.1X.X (TBR)
************

* Add cryptography 2.4.2 to the test-suite.
* Remove colons from CA private keys (fixes `#29 <https://github.com/mathiasertl/django-ca/issues/28>`_).
* Filenames for downloading certificates are based on the CommonName (fixes 
  `#53 <https://github.com/mathiasertl/django-ca/issues/53>`_).
* Fix certificate bundle order (fixes `#55 <https://github.com/mathiasertl/django-ca/issues/55>`_).
* Management commands ``dump_ca`` and ``dump_cert`` can now dump whole certificate bundles.
* :py:class:`~django_ca.subject.Subject` now implements every ``dict`` method.
* Add the :py:class:`~django_ca.extensions.BasicConstraints`,
  :py:class:`~django_ca.extensions.IssuerAlternativeName` and
  :py:class:`~django_ca.extensions.SubjectAlternativeName`.
* New setting :ref:`CA_DEFAULT_KEY_SIZE <settings-ca-default-key-size>` to configure the default key size
  for new CAs.
* Test for certificates that are not yet valid.
* Freeze time in some test cases to avoid test failures when certificates eventually expire.
* Test some documentation pages, to make sure they are actually correct.

.. _changelog-1.10.0:

*******************
1.10.0 (2018-11-03)
*******************

* New dependency: `django-object-actions <https://github.com/crccheck/django-object-actions>`_.
* Add ability to resign existing certificates.
* Management command ``list_cas`` now optionally supports a tree view.
* Use more consistent naming for extensions throughout the code and documentation.
* Renamed the ``--tls-features`` option of the ``sign_cert`` command to ``--tls-feature``, in line with the 
  actual name of the extension.
* Allow the ``TLSFeature`` extension in profiles.
* Add link in the admin interface to easily download certificate bundles.
* Support ECC private keys for new Certificate Authorities.
* Store CA private keys in the more secure `PKCS8 format
  <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8>`_.
* The Certificate change view now has a second "Revoke" button as object action next to the "History" button.

Python API
==========

* Add the :doc:`Python API <python/intro>` as a fully supported interface to **django-ca**. 
* New module :py:mod:`django_ca.extensions` to allow easy and consistent handling of X509 extensions.
* Fully document various member attributes of :py:class:`~django_ca.models.CertificateAuthority` and
  :py:class:`~django_ca.models.Certificate`, as well :py:class:`~django_ca.subject.Subject` and
  as all new Python code.
* The parameters for functions in :py:class:`~django_ca.managers.CertificateManager` and
  :py:meth:`~django_ca.managers.CertificateAuthorityManager.init` were cleaned up for consistent naming and so
  that a user no longer needs to use classes from the cryptography libary. Parameters are now optional if
  default settings exist.
* Variable names have been renamed to be more consistent to make the code more readable.

Testing
=======

* Also test with Python 3.7.0.
* Add configuration for `tox <https://tox.readthedocs.io/en/latest/>`_.
* Speed up test-suite by using :py:meth:`~django:django.test.Client.force_login` and
  `PASSWORD_HASHERS <https://docs.djangoproject.com/en/dev/topics/testing/overview/#password-hashing>`_.
* Load keys and certs in for every testcase instead for every class, improving testcase isolation.
* Add two certificates that include all and no extensions at all respectively to be able to test edge cases
  more consistently and thoroughly.
* Add function ``cmd_e2e`` to call ``manage.py`` scripts in a way that arguments are passed by argparse as if
  they where called from the command-line. This allows more complete testing including parsing commandline
  arguments.
* Error on any :py:mod:`python:warnings` coming from django-ca when running the test-suite.

.. _changelog-1.9.0:

******************
1.9.0 (2018-08-25)
******************

* Allow the creation of Certificates with multiple OUs in their subject (command-line only).
* Fix issues with handling CAs with a password on the command-line.
* Fix handling of certificates with no CommonName and/or no x509 extensions.
* Add support for displaying Signed Certificate Timestamps (SCT) Lists, as described in
  `RFC 6962, section 3.3 <https://tools.ietf.org/html/rfc6962#section-3.3>`_.
* Add limited support for displaying Certificate Policies, as described in
  `RFC 5280, section 4.2.14 <https://tools.ietf.org/html/rfc5280#section-4.2.1.4>`_ and
  `RFC 3647 <https://tools.ietf.org/html/rfc3647>`_.
* Correctly display extensions with an OID unknown to django-ca or even cryptography.
* Properly escape x509 extensions to prevent any injection attacks.
* Django 2.1 is now fully supported.
* Fix example command to generate a CSR (had a stray '/').
* Run test-suite with template debugging enabled to catch silently skipped template errors.

Docker
======

* Base the :doc:`Docker image <docker>` on ``python:3-alpine`` (instead of ``python:3``), yielding a much
  smaller image (~965MB -> ~235MB).
* Run complete test-suite in a separate build stage when building the image.
* Provide ``uwsgi.ini`` for fast deployments with the uwsgi protocol.
* Add support for passing additional parameters to uWSGI using the ``DJANGO_CA_UWSGI_PARAMS`` environment
  variable.
* Create user/group with a predefined uid/gid of 9000 to allow better sharing of containers.
* Add ``/usr/share/django-ca/`` as named volume, allowing a setup where an external webserver serves static
  files.
* Add documentation on how to run the container in combination with an external webserver.
* Add documentation on how to run the container as a different uid/gid.

.. _changelog-1.8.0:

******************
1.8.0 (2018-07-08)
******************

* Add :doc:`Django signals </signals>` to important events to let users add custom actions (such as email
  notifications etc.) to those events (fixes `#39 <https://github.com/mathiasertl/django-ca/issues/39>`_).
* Provide a Docker container for fast deployment of **django-ca**.
* Add the :ref:`CA_CUSTOM_APPS <settings-ca-custom-apps>` setting to let users that use **django-ca** as a
  :ref:`standalone project <as-standalone>` add custom apps, e.g. to register signals.
* Make the ``otherName`` extension actually usable and tested (see `PR47
  <https://github.com/mathiasertl/django-ca/pull/47>`_)
* Add the ``smartcardLogon`` and ``msKDC`` extended key usage types. They are needed for some AD and OpenLDAP
  improvements (see `PR46 <https://github.com/mathiasertl/django-ca/pull/46>`_)
* Improve compatability with newer ``idna`` versions (``".com"`` now also throws an error).
* Drop support for Django 1.8 and Django 1.10.
* Improve support for yet-to-be-released Django 2.1.
* Fix admin view of certificates with no subjectAltName.

.. _changelog-1.7.0:

******************
1.7.0 (2017-12-14)
******************

* Django 2.0 is now fully supported. This release still supports Django 1.8, 1.10 and 1.11.
* Add support for the :ref:`TLSFeature <extension-tls-feature>` extension.
* Do sanity checks on the "pathlen" attribute when creating Certificate Authorities.
* Add sanity checks when creating CAs:

  * When creating an intermediate CA, check the ``pathlen`` attribute of the parent CA to make sure that the
    resulting CA is not invalid.
  * Refuse to add a CRL or OCSP service to root CAs. These attributes are not meaningful there.

* Massively update :doc:`documentation for the command-line interface </cli/intro>`.
* CAs can now be identified using name or serial (previously: only by serial) in 
  :ref:`CA_OCSP_URLS <settings-ca-ocsp-urls>`.
* Make ``fab init_demo`` a lot more useful by signing certificates with the client CA and include CRL and OCSP
  links.
* Run ``fab init_demo`` and documentation generation through Travis-CI.
* Always display all extensions in the django admin interface.
* NameConstraints are now delimited using a ``,`` instead of a ``;``, for consistency with other parameters
  and so no bash special character is used.

Bugfixes
========

* Check for permissions when downloading certificates from the admin interface. Previously, users without
  admin interface access but without permissions to access certificates, where able to guess the URL and
  download public keys.
* Add a missing migration.
* Fix the value of the crlDistributionPoints x509 extension when signing certificates with Python2.
* The ``Content-Type`` header of CRL responses now defaults to the correct value regardless of type (DER or
  PEM) used.
* If a wrong CA is specified in :ref:`CA_OCSP_URLS <settings-ca-ocsp-urls>`, an OCSP internal error is
  returned instead of an uncought exception.
* Fix some edge cases for serial conversion in Python2. Some serials where converted with an "L" prefix in
  Python 2, because ``hex(0L)`` returns ``"0x0L"``.

.. _changelog-1.6.3:

******************
1.6.3 (2017-10-21)
******************

* Fix various operations when ``USE_TZ`` is ``True``.
* Email addresses are now independently validated by ``validate_email``. cryptography 2.1 no longer validates
  email addresses itself.
* Require ``cryptography>=2.1``. Older versions should not be broken, but the output changes breaking
  doctests, meaning they're no longer tested either.
* CA keys are no longer stored with colons in their filename, fixing ``init_ca`` under Windows.

.. _changelog-1.6.2:

******************
1.6.2 (2017-07-18)
******************

* No longer require a strict cryptography version but only ``>=1.8``. The previously pinned version is
  incompatible with Python 3.5.
* Update requirements files to newest versions.
* Update imports to ``django.urls.reverse`` so they are compatible with Django 2.0 and 1.8.
* Make sure that ``manage.py check`` exit status is not ignored for ``setup.py code_quality``.
* Conform to new sorting restrictions for ``isort``.

.. _changelog-1.6.1:

******************
1.6.1 (2017-05-05)
******************

* Fix signing of wildcard certificates (thanks `RedNixon <https://github.com/mathiasertl/django-ca/pull/25>`_).
* Add new management commands ``import_ca`` and ``import_cert`` so users can import existing CAs and
  certificates.

.. _changelog-1.6.0:

******************
1.6.0 (2017-04-21)
******************

New features and improvements
=============================

* Support CSRs in DER format when signing a certificate via ``manage.py sign_cert``.
* Support encrypting private keys of CAs with a password.
* Support Django 1.11.
* Allow creating CRLs of disabled CAs via ``manage.py dump_crl``.
* Validate DNSNames when parsing general names. This means that signing a certificate with CommonName that is
  not a valid domain name fails if it should also be added as subjectAltName (see ``--cn-in-san`` option).
* When configuring :py:class:`~django_ca.views.OCSPView`, the responder key and certificate are verified
  during configuration. An erroneous configuration thus throws an error on startup, not during runtime.
* The testsuite now tests certificate signatures itself via ``pyOpenSSL``,  so an independent library is used
  for verification.

Bugfixes
========

* Fix the ``authorityKeyIdentifier`` extension when signing certificates with an intermediate CA.
* Fix creation of intermediate CAs.

.. _changelog-1.5.1:

******************
1.5.1 (2017-03-07)
******************

* Increase minimum field length of serial and common name fields.
* Tests now call full_clean() for created models. SQLite (which is used for testing) does not enforce the
  ``max_length`` parameter.

.. _changelog-1.5.0:

******************
1.5.0 (2017-03-05)
******************

* Completely remove pyOpenSSL and consistently use `cryptography <https://cryptography.io/>`_.
* Due to the transitition to cryptography, some features have been removed:

  * The ``tlsfeature`` extension is no longer supported. It will be again once cryptography adds support.
  * The ``msCodeInd``, ``msCodeCom``, ``msCTLSign``, ``msEFS`` values for the ExtendedKeyUsage extension are
    no longer supported. Support for these was largely academic anyway, so they most likely will not be added
    again.
  * ``TEXT`` is no longer a supported output format for dumping certificates.

* The ``keyUsage`` extension is now marked as critical for certificate authorities.
* Add the ``privilegeWithdrawn`` and ``aACompromise`` attributes for revocation lists.

.. _changelog-1.4.1:

******************
1.4.1 (2017-02-26)
******************

* Update requirements.
* Use `Travis CI <https://travis-ci.org>`_ for continuous integration. **django-ca** is now tested
  with Python 2.7, 3.4, 3.5, 3.6 and nightly, using Django 1.8, 1.9 and 1.10.
* Fix a few test errors for Django 1.8.
* Examples now consistently use 4096 bit certificates.
* Some functionality is now migrated to ``cryptography`` in the ongoing process to deprecate
  pyOpenSSL (which is no longer maintained).
* OCSPView now supports directly passing the public key as bytes. As a consequence, a bad
  certificate is now only detected at runtime.

.. _changelog-1.4.0:

******************
1.4.0 (2016-09-09)
******************

* Make sure that Child CAs never expire after their parents. If the user specifies an expiry after
  that of the parent, it is silently changed to the parents expiry.
* Make sure that certificates never expire after their CAs. If the user specifies an expiry after
  that of the parent, throw an error.
* Rename the ``--days`` parameter of the ``sign_cert`` command to ``--expires`` to match what we
  use for ``init_ca``.
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
