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

   $ python manage.py init_ca --password=mypassword CAInDefaultKeyBackend CN=Default
   $ python manage.py init_ca --key-backend=hsm \
   >     --hsm-key-label=my_key_label --hsm-user-pin=1234 \
   >     CAInHSM CN=HSM

If you run any command with ``--help``, you'll see all currently valid options.

******************
Supported backends
******************

.. _storages_backend:

:spelling:word:`Storages` backend
=================================

.. autoclass:: django_ca.key_backends.storages.StoragesBackend

.. _hsm_backend:

HSM (Hardware Security Module) backend
======================================

.. autoclass:: django_ca.key_backends.hsm.HSMBackend

.. _hsm_backend_pins:

HSM pin handling
================

Any operation must either use an SO pin or a user pin. The configuration in ``CA_KEY_BACKENDS`` should
provide the pin required for signing operations, usually the user pin.

If creating a new certificate authority requires an SO pin instead, you can specify it on the command line.
However, you must also disable the user pin in this case. For example (assuming the HSM backend is your
default backend):

.. code-block:: console

   $ python manage.py init_ca --so-pin=1234 --user-pin="" ...