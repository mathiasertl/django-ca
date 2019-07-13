###############
Release process
###############

**************
Before release
**************

* Update ``requirements*.txt`` (use ``pip list -o``).
* Make sure that ``setup.py`` has proper requirements.
* Make sure that ``setup.py`` has proper classifiers, if support for some Python or Django versions was
  added/dropped.
* Check ``.travis.yaml`` if the proper Django and cryptography versions are tested.
* Check test coverage (``setup.py coverage``).
* Update ``version`` parameter in ``setup.py``.
* Update ``VERSION`` and ``__version__`` in ``ca/django_ca/__init__.py``
  (see `PEP 440 <https://www.python.org/dev/peps/pep-0440/>`_).
* Make sure that ``docs/source/changelog.rst`` is up to date.
* Make sure that tox runs through for all environments.
* Make sure that ``python dev.py docker-test`` runs through.
* Make sure that the admin interface displays certificates correctly.
* Push the last commit and make sure that Travis and Read The Docs are updated.

*********
Test demo
*********

Make sure that the demo works::

   rm -rf ca/db.sqlite3 ca/files/
   ./dev.py init-demo
   
   # test commands from the output:
   openssl verify -CAfile...

************
Docker image
************

Create a docker image::

   docker build --no-cache -t django-ca-dev .
   docker run --rm -d --name=django-ca-dev -p 8000:8000 django-ca-dev
   docker exec -it django-ca-dev python ca/manage.py createsuperuser
   docker exec -it django-ca-dev python ca/manage.py init_ca \
      example /C=AT/ST=Vienna/L=Vienna/O=Org/CN=ca.example.com

... and browse http://localhost:8000/admin.

***************
Release process
***************

* Tag the release: ``git tag -s $version``
* Push the tag: ``git push origin --tags``
* Create a `release on GitHub <https://github.com/mathiasertl/django-ca/tags>`_.
* Upload release to PyPI: ``python setup.py sdist bdist_wheel upload``.
* Tag and upload the docker image  (note that we create a image revision by appending ``-1``)::

      docker tag django-ca-dev mathiasertl/django-ca
      docker tag django-ca-dev mathiasertl/django-ca:$version
      docker tag django-ca-dev mathiasertl/django-ca:$version-1
      docker push mathiasertl/django-ca:$version-1
      docker push mathiasertl/django-ca:$version
      docker push mathiasertl/django-ca

***************
After a release
***************

* Update ``VERSION`` and ``__version__`` in ``ca/django_ca/__init__.py`` to the next
  development release (see `PEP 440 <https://www.python.org/dev/peps/pep-0440/>`_).
* Update version in ``setup.py``.
