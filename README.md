# django-ca

django-ca provides you with a local TLS certificate authority. It is based on
[pyOpenSSL](https://pyopenssl.readthedocs.org/) and [Django](https://www.djangoproject.com/>), it
can be used as an app in an existing Django project or with the basic project included.
Certificates can be managed through Djangos admin interface or via `manage.py` commands - no
webserver is needed, if you’re happy with the command-line.

## Features

1. Set up a secure local certificate authority in just a few minutes.
2. Written in Python3.4+.
3. Manage your entire certificate authority from the command line and/or via
   Djangos admin interface.
4. Get email notifications about certificates about to expire.
5. Support for certificate revocation lists (CRLs) and OCSP (both have to be
   hosted separately).

Please see https://django-ca.readthedocs.org for more extensive documentation.

## ChangeLog

See ChangeLog.md.

## ToDo

Ideas on what we could do for future releases:

1. Only send out one notification if multiple certificates expire for a user.
2. Add a "renew" button in the admin interface.
3. Admin interface should account for cases where the private key is not present.
4. Add ability to automatically regenerate CRLs when a certificate is revoked.
5. Add a generic view to provide a CRL.
6. Add a OCSP service maybe (would be huge).
7. Print HPKP hashes with the `view_ca` and `view_cert` commands.

## Test CRL and OCSP

To create a demo certificate authority with an OCSP responder, configure a minimal
`ca/ca/localsettings.py`:

```
DEBUG = True
SECRET_KEY = "whatever"
```

and simply execute the `init_demo` fabfile target:

```
fab init_demo
```

This will create all certificates in `ca/files`, a user named `user` with the password `nopass` and
tell you how to run the OCSP responder and verify via CRL and OCSP. Four server certificates are
created, `host1.example.com` through `host4.example.com`, the first two are revoked.

## License

This project is free software licensed under the [GPLv3](http://www.gnu.org/licenses/gpl.txt).
