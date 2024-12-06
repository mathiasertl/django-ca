############
Key backends
############

**django-ca** allows you to store private keys of certificate authorities as files (on the file system or
any other system supported via the `Django file storage API
<https://docs.djangoproject.com/en/5.0/ref/files/storage/>`_) or in a hardware security module (HSM) using the
#PKCS 11 protocol.

You can even write your own backend for storing private keys to handle private keys in more unique ways, see
:ref:`writing custom backends <custom_key_backends>` for more information.

*********************
Default configuration
*********************

The default configuration is to store private keys on the file system. This works on any system, but is not
the most secure method possible.

.. tab:: Python

   .. literalinclude:: /include/config/settings_default_ca_key_backends.py
      :language: python

.. tab:: YAML

   .. literalinclude:: /include/config/settings_default_ca_key_backends.yaml
      :language: YAML

*****************
Multiple backends
*****************

You can configure multiple backends using the :ref:`settings-ca-key-backends` setting. For example, if you
want to be able to store private keys on the file system, but also in a hardware security module (HSM):

.. tab:: Python

   .. literalinclude:: /include/config/settings_multiple_ca_key_backends.py
      :language: python

.. tab:: YAML

   .. literalinclude:: /include/config/settings_multiple_ca_key_backends.yaml
      :language: YAML

Command-line options added by any backend that is not named "default" will be prefixed with the name of the
backend. In the above example, you can use the ``--password`` option normally (which is added by the default
backend), but you must use ``--hsm-user-pin`` etc. when using the HSM key backend:

.. code-block:: console

   user@host:~$ python manage.py init_ca --password=mypassword CAInDefaultKeyBackend CN=Default
   user@host:~$ python manage.py init_ca --key-backend=hsm \
   >     --hsm-key-label=my_key_label --hsm-user-pin=1234 \
   >     CAInHSM CN=HSM

If you run any command with ``--help``, you'll see all currently valid options.

******************
Supported backends
******************

.. _storages_backend:

:spelling:word:`Storages` backend
=================================

The most common use case for this key backend is to store keys on the local file system. However, you can
use any custom Django storage system, for example from `django-storages
<https://django-storages.readthedocs.io/en/latest/>`_.

This backend takes a single option, ``storage_alias``. It defines the storage system (as defined in
`STORAGES <https://docs.djangoproject.com/en/5.0/ref/settings/#std-setting-STORAGES>`_) to use.
The default configuration is a good example:

.. tab:: Python

   .. literalinclude:: /include/config/settings_default_ca_key_backends.py
      :language: python

.. tab:: YAML

   .. literalinclude:: /include/config/settings_default_ca_key_backends.yaml
      :language: YAML

.. seealso::

   * `STORAGES setting <https://docs.djangoproject.com/en/5.0/ref/settings/#std-setting-STORAGES>`_
   * `Django file storage API <https://docs.djangoproject.com/en/5.0/ref/files/storage/>`_
   * `django-storages <https://django-storages.readthedocs.io/en/latest/>`_

.. _hsm_backend:

HSM (Hardware Security Module) backend
======================================

The HSM backend provides the ability to store private keys in a Hardware Security Module (HSM) via the
`PKCS 11 protocol <https://en.wikipedia.org/wiki/PKCS_11>`_ and `python-pkcs11
<https://python-pkcs11.readthedocs.io/>`_.

When using :doc:`Docker </quickstart/docker>` or :doc:`docker-compose </quickstart/docker_compose>`, you need
to make sure that the PKCS 11 library as well as the hardware device is available in the Docker container.

When using django-ca :doc:`as a Django app </quickstart/as_app>` or if you :doc:`installed from source
</quickstart/from_source>`, you have to install django-ca with the ``hsm`` extra, e.g.

.. code-block:: console

   user@host:~$ pip install django-ca[hsm]

This backend has several mandatory options:

    * `library_path` specifies the path to the PKCS11 library (e.g.
      ``/usr/lib/softhsm/libsofthsm2.so`` for SoftHSM2 on Debian/Ubuntu).
    * `token` to specify the token to use.
    * Either an `so_pin` or `user_pin` (can be overwritten on the command-line).

For example:

.. tab:: Python

   .. literalinclude:: /include/config/settings_hsm_backend.py
      :language: python

.. tab:: YAML

   .. literalinclude:: /include/config/settings_hsm_backend.yaml
      :language: YAML

Usage via the command-line
--------------------------

Assuming the HSM backend is the default backend, you can create a certificate authority and sign a certificate
like this:

.. code-block:: console

   user@host:~$ python manage.py init_ca --key-label=my-key-label --user-pin=1234 CAInHSM CN=ca.example.com
   user@host:~$ python manage.py sign_cert --ca=... --alt=example.com

If the HSM backend is not the default backend but uses the name ``"hsm"``, you have to explicitly name the key
backend and prefix options accordingly:

.. code-block:: console

    user@host:~$ python manage.py init_ca \
    >     --key-backend=hsm --hsm-key-label=my-key-label --hsm-user-pin=1234 \
    >     CAInHSM CN=ca.example.com
    user@host:~$ python manage.py sign_cert --ca=... --alt=example.com

.. _hsm_backend_pins:

HSM pin handling
----------------

Any operation must either use an SO pin or a user pin. The configuration in ``CA_KEY_BACKENDS`` should
provide the pin required for signing operations, usually the user pin.

If creating a new certificate authority requires an SO pin instead, you can specify it on the command line.
However, you must also disable the user pin in this case. For example (assuming the HSM backend is your
default backend):

.. code-block:: console

   user@host:~$ python manage.py init_ca --so-pin=1234 --user-pin="" ...

.. _ocsp_key_backends:

*****************
OCSP Key backends
*****************

Just like for certificate authorities, **django-ca** allows you to store private keys for OCSP responder
certificates using different backends. By default, private keys are stored on the file system, but they can
also be stored in a Hardware Security Module.

Note that the OCSP key storage method does not have to match the method used for storing the private key of
the certificate authority.

There are two things fundamentally different about OCSP key backends compared to CA key backends:

1. The *private* key must be accessible by the web server to sign OCSP responses. This might be tricky in
   setups where the private key of the certificate authority is stored on a different host from the web
   server.
2. The web server must be able to use the private key non-interactively. That means that all information to
   access the private key (including e.g. passwords) must either be in settings or the database.

Configuring the OCSP key backend
================================

The available key backends can be configured using the :ref:`CA_OCSP_KEY_BACKENDS
<settings-ca-ocsp-key-backends>` option.

The OCSP key backend that is used for a specific certificate authority can be configured using the admin
interface or with the `--ocsp-key-backend` option to :command:`manage.py init_ca`,
:command:`manage.py edit_ca` and :command:`manage.py import_ca`. Note that when you change the backend,
you must manually regenerate OCSP keys (e.g. using :command:`manage.py regenerate_ocsp_keys`.

:spelling:word:`Storages` OCSP key backend
==========================================

This backend is equivalent to the :ref:`storages_backend` backend and stores keys on the file system.

By default, private keys are encrypted with a random password before written to the files system, with the
private key stored in the database. This provides a modest security benefit in some setups.

The backend takes three options: ``storage_alias`` has the same meaning as in the :spelling:word:`storages`
backend, ``path`` defines a sub-directory where to store keys. The ``encrypt_private_key`` can be set to false
to disable encryption of private keys with a random password:

.. tab:: Python

   .. literalinclude:: /include/config/settings_storages_ocsp_key_backend.py
      :language: python

.. tab:: YAML

   .. literalinclude:: /include/config/settings_storages_ocsp_key_backend.yaml
      :language: YAML

HSM (Hardware Security Module) OCSP key backend
===============================================

The HSM OCSP key backend is equivalent to the :ref:`hsm_backend`. It takes the same options as the normal
backend:

.. tab:: Python

   .. literalinclude:: /include/config/settings_hsm_ocsp_key_backend.py
      :language: python

.. tab:: YAML

   .. literalinclude:: /include/config/settings_hsm_ocsp_key_backend.yaml
      :language: YAML
