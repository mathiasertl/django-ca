
============== ==============================================================================================
Extra          Description
============== ==============================================================================================
``redis``      Adds `Redis <https://redis.io/>`_ support (usable as both cache and Celery message transport).
``celery``     Adds `Celery <https://docs.celeryproject.org/>`_ support.
``mysql``      Adds MySQL support.
``postgres``   Adds PostgreSQL support.
============== ==============================================================================================

.. deprecated:: 1.21.0

   The ``acme`` extra is deprecated and will be removed in ``django-ca==1.23.0``. The dependencies it
   installed are now mandatory.
