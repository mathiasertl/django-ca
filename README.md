# django-ca

![image](https://github.com/mathiasertl/django-ca/workflows/Tests/badge.svg)
![image](https://github.com/mathiasertl/django-ca/workflows/Code%20quality/badge.svg)
![image](https://img.shields.io/pypi/v/django-ca.svg)
![image](https://img.shields.io/pypi/dm/django-ca.svg)
![image](https://img.shields.io/pypi/pyversions/django-ca.svg)
![image](https://img.shields.io/pypi/status/django-ca.svg)
![image](https://img.shields.io/github/license/mathiasertl/django-ca)

## About

**django-ca** is a tool to manage TLS certificate authorities and easily issue and revoke certificates. It is
based on [cryptography](https://cryptography.io/) and [Django](https://www.djangoproject.com/>). It can be used as an app in an existing Django project or
stand-alone with the basic project included. Certificates can be managed through Django's admin interface or
via `manage.py` commands - so no webserver is needed, if you’re happy with the command-line.

Documentation is available at https://django-ca.readthedocs.org/.

## Features

1. Set up a secure local certificate authority in just a few minutes.
2. Certificate issuance via ACMEv2, REST API, command line or web interface.
3. Certificate revocation via CRLs and OCSP.
4. Private key storage on the file system, in the database or in a Hardware Security Module (HSM).
5. Management via command line and/or via Django's admin interface.
6. Get email notifications about expiring certificates.
7. Written in Python 3.11+, Django 5.2+ and cryptography 46+.

Please see https://django-ca.readthedocs.org for more extensive documentation.

## Documentation

Documentation is available at https://django-ca.readthedocs.org/.

## ChangeLog

Please see https://django-ca.readthedocs.io/en/latest/changelog.html

## License

This project is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl.txt).
