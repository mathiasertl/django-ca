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
2. Written in Python 3.6+, Django 2.2+ and cryptography 2.8+.
3. Preliminary ACMEv2 support.
3. Management via command line and/or via Djangos admin interface.
4. Certificate revocation via CRLs and OCSP.
5. Get email notifications about certificates about to expire.

Please see https://django-ca.readthedocs.org for more extensive documentation.

## Documentation

Documentation is available at https://django-ca.readthedocs.org/.

## ChangeLog

Please see https://django-ca.readthedocs.io/en/latest/changelog.html

## ToDo

Ideas on what we could do for future releases:

1. Test CRL signing certificates.
2. Only send out one notification if multiple certificates expire for a user.
3. Add ability to automatically regenerate CRLs when a certificate is revoked.

## License

This project is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl.txt).
