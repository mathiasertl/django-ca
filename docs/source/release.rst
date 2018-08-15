###############
Release process
###############

**************
Before release
**************

* Update ``requirements*.txt`` (use ``pip list -o``).
* Make sure that ``setup.py`` has proper requirements.
* Check ``.travis.yaml`` if the proper Django and cryptography versions are tested.
* Update ``version`` parameter in ``setup.py``.
* Update ``version`` and ``release`` in ``docs/source/conf.py``.
* Make sure that ``docs/source/changelog.rst`` is up to date.
* Push the last commit and make sure that Travis and Read The Docs are updated.

************
Docker image
************

Create a docker image (note that we create a image revision by appending ``-1``)::

   docker build --no-cache -t django-ca .
   docker run -d --name=django-ca -p 8000:8000 django-ca
   docker exec -it django-ca python ca/manage.py createsuperuser
   docker exec -it django-ca python ca/manage.py init_ca \
      example /C=AT/ST=Vienna/L=Vienna/O=Org/CN=ca.example.com

... and browse http://localhost:8000/admin.

***************
Release process
***************

* Tag the release: ``git tag -s $version``
* Push the tag: ``git push origin --tags``
* Create a `release on GitHub <https://github.com/mathiasertl/django-ca/tags>`_.
* Upload release to PyPI: ``python setup.py sdist bdist_wheel upload``.
* Tag and upload the docker image:

      docker tag django-ca mathiasertl/django-ca
      docker tag django-ca mathiasertl/django-ca:$version-1
      docker push mathiasertl/django-ca
      docker push mathiasertl/django-ca:$version-1
