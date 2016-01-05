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

## Management

Certificate management is done via ``manage.py``. In general, all commands have a ``-h`` option.

### Creating a private key

Like any good CA, this project does never creates private certificates for you. Instead, create a
private certificate and certificate-signing request (CSR) on the machine that will use the
certificate:

```
openssl genrsa -out example.com.key 4096
openssl req -new -key example.com.key -out example.com.csr -utf8 -sha512
```

### Sign a private key

Copy the CSR and sign it:

```
python ca/manage.py sign_cert --csr example.com.csr --out example.com.crt
```

Note that the ``sign_cert`` command has a few useful options, try the ``-h`` parameter for options.

### List certificates/View certificate

To get a list of all certificates, use ``manage.py list_certs``, to view details of a certificate,
use `manage.py view_cert` (`$` signals the shell prompt):

```
$ python manage.py list_certs
BBB6B79C12604B1BB32E7DBC08942410: test.example.com (expires: 2017-01-28)
$ python ca/manage.py view_cert BBB6B79C12604B1BB32E7DBC08942410
...
```

### Revoke a certificate

To revoke a certificate, use

```
python ca/manage.py revoke <serial>
```

The serial can be optained via ``python ca/manage.py list_certs``.

### Add/Remove watchers to certificates

You can add/remove watchers (users that get emails about certificates about to
expire) using ``manage.py cert_watchers``.

## Regular cron-jobs

It is recommended you execute this job daily via cron, but non are required for basic operations:

```
# assuming you cloned the repo at /root/:
HOME=/root/django-ca
PATH=/root/django-ca/bin

# m h  dom mon dow     user           command

# notify watchers about certificates about to expire
* 8    * * *           xmpp-account   python ca/manage.py notify_expiring_certs

# recreate the CRL and the OCSP index
12 *    * * *           xmpp-account   python ca/manage.py dump_crl
14 *    * * *           xmpp-account   python ca/manage.py dump_ocsp_index
```

## ChangeLog

See ChangeLog.md.

## ToDo

1. Add setting for location of CRL and OCSP index (so we can automatically dump).
2. Immediately rewrite CRL and index file when revoking a certificate.
3. Only send out one notification if multiple certificates expire for a user.
4. Add a 'renew' button in the admin interface.
5. Publish good documentation on RTD.

## Test CRL and OCSP

To create a demo certificate authority with an OCSP responder, simply use the `init_demo` fabfile
target:

```
fab init_demo
```

This will create all certificates in `ca/files` and tell you how to run the OCSP responder and
verify via CRL and OCSP. Four server certificates are created, `host1.example.com` through
`host4.example.com`, the first two are revoked.

## License

This project is free software licensed under the [GPLv3](http://www.gnu.org/licenses/gpl.txt).
