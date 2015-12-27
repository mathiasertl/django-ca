# django-ca

This Django app allows you to manage a local TLS certificate authority. The app can be included in
any Django project or used with the example project included. Certificates can be managed through
Djangos admin interface or via `manage.py` commands - no webserver is needed, if you're happy with
the command-line.

## Features

1. Set up a secure certification authority in a few minutes.
2. Manage your entire certificate authority from the command line and/or via Djangos admin
   interface.
3. Written in pure Python using [pyOpenSSL](pythonhosted.org/pyOpenSSL/) and the ORM of
   [Django](https://www.djangoproject.com/).
4. Get email notifications about certificates about to expire.
5. Support for certificate revocation lists (CRLs) and OCSP (both have to be hosted separately).

## Setup

You will need the development headers required by pyOpenSSL, on Debian/Ubuntu
systems, this should suffice:

```
apt-get install gcc python3-dev libffi-dev libssl-dev
```

Next, download the project, create a virtualenv, install requirements:

```
git clone https://github.com/mathiasertl/django-ca
cd django-ca
virtualenv -p /usr/bin/python3 .
source bin/activate
pip install -r requirements.txt
```

Copy ``ca/ca/localsettings.py.example`` to ``ca/ca/localsettings.py`` and make
the necesarry adjustments. 

Then create the certificate authority ("CA"), the arguments is required certificate information,
fill in our own data:

```
python ca/manage.py init_ca AT Vienna Vienna "HTU Wien" "Fachschaft Informatik" ca.fsinf.at
```

**Note:** You can set some options for your CA, try the ``-h`` parameter.

## Configuration

The file ``ca/ca/localsettings.py.example`` contains documentation on available settings.

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

# recreate the CRL (hourly), also creates an OpenSSL CA index file and a pem with the CA cert and
# the CRL (required for "openssl ocsp")
12 *    * * *           xmpp-account   python ca/manage.py dump_crl
```

## ChangeLog

See ChangeLog.md.

## ToDo

1. Write man-page for scripts.
2. Immediately rewrite CRL and index file when revoking a certificate.
3. Only send out one notification if multiple certificates expire for a user.

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
