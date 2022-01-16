##############
ACMEv2 support
##############

**django-ca** has preliminary ACMEv2 support that allows you to retrieve certificates via certbot or other
standard ACME clients.

.. WARNING::

   Support for ACME is preliminary and must be explicitly activated. Several features are not yet implemented.
   Use this feature only with the necessary caution.

*****************************
Install required dependencies
*****************************

The Docker image already includes all required dependencies, so there is nothing you need to do.

If you install **django-ca** via pip, you can install all required dependencies using the ``acme`` extra:

.. code-block:: console

   $ pip install django-ca[acme]

If you want to install dependencies manually, you need `acme <https://pypi.org/project/acme/>`_ and `requests
<https://pypi.org/project/requests/>`_ (for challenge validation).


*********************
Enable ACMEv2 support
*********************

To enable ACME support, simply set ``CA_ENABLE_ACME=True`` in your settings.

You must enable ACME for each CA individually, either in the admin interface or view the ``edit_ca``
management command.

Enable ACMEv2 for a CA
======================

Additionally to setting ``CA_ENABLE_ACME=True``, a CA can only be used for issuing certificates via ACMEv2 if
explicitly enabled.

You have to enable the feature for every CA individually. You an do so either in the admin interface or via
the command line when creating a CA or editing it:

.. code-block:: console

   $ python manage.py init_ca --acme-enable ...
   $ python manage.py edit_ca --acme-enable ...
   $ python manage.py edit_ca --acme-disable ...

*****************
Known limitations
*****************

ACMEv2 support is preliminary, known to be incomplete and may contain critical bugs. But at least basic
certificate issuance is working.

The following things are known to not yet work:

* Certificate revocation
* Pre-Authorization for certificates
* Account update
* External account bindings
* CAA validation (django-ca will happily issue certificates for google.com etc.)
* Wildcard certificates

*****
Usage
*****

You can retrieve a certificate via ACMEv2 by telling your client to use our CA. For example, if you have your
CA at ``https://ca.example.com``, you can get a certificate with certbot like this:

.. code-block:: console

   $ certbot register --agree-tos -m user@example.net \
   >     --server https://ca.example.com/django_ca/acme/directory/
   $ certbot certonly --standalone \
   >     --server https://ca.example.com/django_ca/acme/directory/
   >     -d test.example.net


Multiple CAs
============

If you want to enable ACMEv2 for multiple CAs, you can append the serial of your CA to your directory URL to
explicitly name the CA you want to use:

.. code-block:: console

   $ python ca/manage.py list_cas
   10:65:9E:... - child
   6C:16:EF:... - root

   # Enable ACMEv2 for both CAs:
   $ python ca/manage.py edit_ca --acme-enable 10:65:9E:...
   $ python ca/manage.py edit_ca --acme-enable 6C:16:EF:...

   # Default directory URL will point to default CA:
   $ curl -qs https://ca.example.com/django_ca/acme/directory/ | jq -r .newAccount
   https://ca.example.com/django_ca/acme/10659E4BB227717336300222791944CD6458021F/new-account/

   # But you can also explicitly name serial in directory URL:
   $ curl -qs https://ca.example.com/django_ca/acme/directory/10:65:9E:.../ | jq .newAccount
   https://ca.example.com/django_ca/acme/10659E4BB227717336300222791944CD6458021F/new-account/
   $ curl -qs https://ca.example.com/django_ca/acme/directory/6C:16:EF:.../ | jq .newAccount
   https://ca.example.com/django_ca/acme/6C16EF06A9B4FD508904E437C39DA56F50D56B10/new-account/

The default CA used is determined by the :ref:`CA_DEFAULT_CA setting <settings-ca-default-ca>` and the
algorithm described there.

********
Settings
********

.. _settings-ca-acme-enable:

CA_ENABLE_ACME
   Default: ``False``

   Enable ACMEv2 support. Without it, all functionality is disabled.

CA_ACME_MAX_CERT_VALIDITY
   Default: ``90``

   Maximum time in days that certificate via ACMEv2 can be valid. Can also be set to a ``timedelta`` object.

CA_ACME_DEFAULT_CERT_VALIDITY
   Default: ``90``

   Default time in days that certificate via ACMEv2 can be valid. Can also be set to a ``timedelta`` object.

CA_ACME_ACCOUNT_REQUIRES_CONTACT
   Default: ``True``

   Set to false to allow creating ACMEv2 accounts without an email address.
