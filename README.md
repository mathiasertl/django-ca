# django-ca

**django-ca** is a small project to manage TLS certificate authorities and easily issue
certificates.  It is based on [cryptography](https://cryptography.io/) and
[Django](https://www.djangoproject.com/>). It can be used as an app in an existing Django project
or stand-alone with the basic project included.  Certificates can be managed through Djangos admin
interface or via `manage.py` commands - so no webserver is needed, if you’re happy with the
command-line.

Documentation is available at https://django-ca.readthedocs.org/.

## Features

1. Set up a secure local certificate authority in just a few minutes.
2. Written in Python2.7/Python3.5+, requires Django 1.11 or later.
3. Manage your entire certificate authority from the command line and/or via
   Djangos admin interface.
4. Get email notifications about certificates about to expire.
5. Certificate validation using Certificate Revocation Lists (CRLs) and via an included OCSP
   responder.

Please see https://django-ca.readthedocs.org for more extensive documentation.

## Documentation

Documentation is available at https://django-ca.readthedocs.org/.

## ChangeLog

Please see https://django-ca.readthedocs.io/en/latest/changelog.html

## ToDo

Ideas on what we could do for future releases:

1. Add parameter to add generic CRL/OCSP URLs to CAs.
2. Test CRL signing certificates.
3. Only send out one notification if multiple certificates expire for a user.
4. Add ability to automatically regenerate CRLs when a certificate is revoked.

## License

This project is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl.txt).
