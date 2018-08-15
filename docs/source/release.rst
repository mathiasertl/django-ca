###############
Release process
###############

Before you release:

* Update ``requirements*.txt`` (use ``pip list -o``).
* Make sure that ``setup.py`` has proper requirements.
* Check ``.travis.yaml`` if the proper Django and cryptography versions are tested.
* Update ``version`` parameter in ``setup.py``.
* Update ``version`` and ``release`` in ``docs/source/conf.py``.
* Make sure that ``docs/source/changelog.rst`` is up to date.
* Push the last commit and make sure that Travis and Read The Docs are updated.

Release process:

* Tag the release: ``git tag -s $version``
* Push the tag: ``git push origin --tags``
* Create a `release on GitHub <https://github.com/mathiasertl/django-ca/tags>`_.
* Upload release to PyPI: ``python setup.py sdist bdist_wheel upload``.
* Create docker image (note that we create a image revision by appending ``-1``)::

      docker build -t django-ca .
      docker tag django-ca mathiasertl/django-ca
      docker tag django-ca mathiasertl/django-ca:$version-1
      docker push mathiasertl/django-ca
      docker push mathiasertl/django-ca:$version-1
