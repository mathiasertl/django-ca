#########################################
``django_ca.key_backends`` - Key backends
#########################################

**django-ca** key backends allow you to store private keys in multiple locations. An interface allows you to
write custom backends as well.

**********************
Supported key backends
**********************

.. autoclass:: django_ca.key_backends.storages.StoragesBackend

***********************
Writing custom backends
***********************

.. warning:: The key backend interface is new and might change in future versions without notice.

Writing a custom key backend allows you to store keys in a custom way, e.g. in a custom Hardware Security
Module (HSM) or using a different library that handles some kind of file storage or dedicated private key
storage. Writing such a key backend will require some skills though. You should know at least:

#. Python
#. Public key cryptography
#. `Pydantic <https://docs.pydantic.dev/latest/>`_ and `Cryptography <https://cryptography.io/en/latest/>`_

Getting started
===============

Implementing a custom key backend requires you to implement a subclass of
:py:class:`~django_ca.key_backends.base.KeyBackend` and up to three
`Pydantic <https://docs.pydantic.dev/latest/>`_ models to handle options. When implementing, it helps to know
that there are essentially three operations, and functions use the appropriate prefix to indicate their
purpose:

#. **Create** a private key.
#. **Store** a private key.
#. **Use** the private key for

   #. For creating a self-signed (= root) certificate authority.
   #. For signing an intermediate certificate authority.
   #. For signing certificates (including OCSP responder certificates).
   #. For signing Certificate Revocation Lists (CRLs).

In this tutorial, we'll write a subset of :py:class:`~django_ca.key_backends.storages.StoragesBackend`. For
simplification, we will always create RSA keys with a variable key size.

Options
=======

The three operations described above will typically each require a different set of options.
:py:class:`~django_ca.key_backends.base.KeyBackend` uses `Pydantic <https://docs.pydantic.dev/latest/>`_ to
load and validate models and pass them around between different functions.

Depending on your needs, options might be stored (or not) in different locations:

#. In the settings (example: ``storage_alias`` in
   :py:class:`~django_ca.key_backends.storages.StoragesBackend`).
#. In the database (example: The path where the certificate is stored on the file system).
#. Given via the command-line (example: The password used to encrypt the private key is not stored).

When implementing :py:class:`~django_ca.key_backends.base.KeyBackend`, you will be able to handle all three
different use cases.

Pydantic Models
===============

First, we will write three Pydantic models to represent the parameters used for creating, storing and using
private keys. Please see the extensive Pydantic documentation (in particular on `validators
<https://docs.pydantic.dev/latest/concepts/validators/>`_) for additional possibilities.

First, let's represent the options required to **create** private keys (via :command:`manage.py init_ca`).
This requires all details about the key itself, and also where to store it:

.. literalinclude:: /include/key_backend_tutorial/create_private_key_options.py
   :language: python

To store private keys (via :command:`manage.py import_ca`), we don't need a key size (the key has already been
generated), but still a path to store it and an optional password to encrypt it:

.. literalinclude:: /include/key_backend_tutorial/store_private_key_options.py
   :language: python

To use the private key (to sign something), we need the password (if one was set), but do not need the path
where the key is stored, as it is stored in the database (more on that later):

.. literalinclude:: /include/key_backend_tutorial/use_private_key_options.py
   :language: python

Note that ``UsePrivateKeyOptions`` must be serializable as JSON, so you cannot use arbitrary types here.

Actual implementation
=====================

Finally, it is time to implement a class based on :py:class:`~django_ca.key_backends.base.KeyBackend`.

For a start, you have to define a generic class that uses your three models as type parameters. This will
allow you to use mypy for strict type checking later. We'll also define some properties for that are used by
various ``manage.py`` commands, as well as options that come from settings and a constructor for some
validation::

    from django_ca.key_backends import KeyBackend


    class MyStoragesBackend(KeyBackend[CreatePrivateKeyOptions, StorePrivateKeyOptions, UsePrivateKeyOptions]):
        """Custom storages implementation."""

        # Used in manage.py commands
        name = "my-storages"
        title = "Store private RSA keys using the Django file storage API"
        description = (
            "It is most commonly used to store private keys on the filesystem. Custom file storage backends can "
            "be used to store keys on other systems (e.g. a cloud storage system)."
        )

        # Used internally:
        use_model = UsePrivateKeyOptions

        # Supported private key parameters. This backend only supports RSA keys.
        supported_key_types = ("RSA",)

        # values from the CA_KEY_BACKENDS setting
        storage_alias: str

        def __init__(self, alias: str, storage_alias: str) -> None:
            if storage_alias not in settings.STORAGES:
                raise ValueError(f"{alias}: {storage_alias}: Storage alias is not configured.")
            super().__init__(alias, storage_alias=storage_alias)

Based on the three operations (create, store or use a private key), there are several functions to implement:

#. ``add_{operation}_arguments()`` gets an `argparse <https://docs.python.org/3/library/argparse.html>`_
   argument group and allows you to add parameters to the respective ``manage.py`` commands.
#. ``get_{operation}_options()`` creates a Pydantic model for that operation based on the arguments added
   above.
#. One or more functions that perform an action. They get at least the database model and a model that
   you created using ``get_{operation}_options()``.

Essentially, all you'll have to do is implement all functions from
:py:class:`~django_ca.key_backends.base.KeyBackend`, and you should have completed the implementation. As an
example, let's demonstrate this for creating private keys, skipping some parameters here:

.. literalinclude:: /include/key_backend_tutorial/create_key_example.py
   :language: python


************************
Base class documentation
************************

.. autoclass:: django_ca.key_backends.base.KeyBackend
   :members:
   :exclude-members: class_path
