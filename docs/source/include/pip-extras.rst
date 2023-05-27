
============= ===============================================================================================
Extra         Description
============= ===============================================================================================
``redis``     Adds `Redis <https://redis.io/>`_ support (usable as both cache and Celery message transport).
``celery``    Adds `Celery <https://docs.celeryproject.org/>`_ support.
``mysql``     Adds MySQL support.
``postgres``  Adds PostgreSQL support using `psycopg2 <https://pypi.org/project/psycopg2/>`_. This will
              switch to Psycopg3 once support for Django 3.2 is dropped.
``psycopg3``  Adds PostgreSQL support using `Psycopg 3 <https://pypi.org/project/psycopg/>`_. This extra will
              be removed once support for Django 3.2 is dropped.
============= ===============================================================================================
