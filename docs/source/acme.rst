##############
ACMEv2 support
##############

**django-ca** has preliminary ACMEv2 support that allows you to retrieve certificates via certbot or other
standard ACME clients.

*************
Configuration
*************

There are some more settings for ACMEv2 support, please see :ref:`settings-acme` for more information.

You must enable ACME for each CA individually, either in the admin interface or via the ``edit_ca`` management
command.

Enable ACMEv2 for a CA
======================

A CA can only be used for issuing certificates via ACMEv2 if explicitly enabled.  You have to enable the
feature for every CA individually. You an do so either in the admin interface or via the command line when
creating a CA or editing it:

.. code-block:: console

   $ python manage.py init_ca --acme-enable ...
   $ python manage.py edit_ca --acme-enable ...
   $ python manage.py edit_ca --acme-disable ...

*****************
Known limitations
*****************

The following things are known to not yet work:

* Pre-Authorization for certificates
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
