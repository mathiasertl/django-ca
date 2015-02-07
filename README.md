# fsinf-certificate-authority

This simple project allows you to manage a local TLS certificate authority from the command line.

## Features

1. Set up a secure certification authority in a few minutes.
2. Manage your entire certificate authority from the command line.
3. Get email notifications about certificates about to expire.
4. Support for certificate revocation lists (CRLs) and OCSP (both have to be hosted separately).

## Setup

First, download the project, create a virtualenv, install requirements:

```
git clone https://github.com/fsinf/certificate-authority.git
cd certificate-authority
virtualenv .
source bin/activate
pip install -r requirements.txt
```

Copy ``ca/ca/localsettings.py.example`` to ``ca/ca/localsettings.py`` and make
the necesarry adjustments. 

Then create the certificate authority ("CA"), the arguments is required certificate information,
fill in our own data:

```
python ca/manage.py init AT Vienna Vienna "HTU Wien" "Fachschaft Informatik" ca.fsinf.at
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
python ca/manage.py sign --csr example.com.csr --out example.com.crt
```

Note that the ``sign`` command has a few useful options, try the ``-h`` parameter for options.

### List certificates/View certificate

To get a list of all certificates, use ``manage.py list``, to view details of a certificate,
use ``manage.py view`` (``$`` signals the shell prompt):

```
$ python manage.py list
BBB6B79C12604B1BB32E7DBC08942410: test.example.com (expires: 2017-01-28)
$ python ca/manage.py view BBB6B79C12604B1BB32E7DBC08942410
...
```

### Revoke a certificate

To revoke a certificate, use

```
python ca/manage.py revoke <serial>
```

The serial can be optained via ``python ca/manage.py list``.

### Add/Remove watchers to certificates

You can add/remove watchers (users that get emails about certificates about to
expire) using ``manage.py watchers``.

## Regular cron-jobs

It is recommended you execute this job daily via cron, but non are required for basic operations:

```
# assuming you cloned the repo at /root/:
HOME=/root/certificate-authority
PATH=/root/certificate-authority/bin

# m h  dom mon dow     user           commanda

# notify watchers about certificates about to expire
* 8    * * *           xmpp-account   python ca/manage.py watch

# recreate CRL (hourly)
12 *    * * *           xmpp-account   python ca/manage.py crl
```

## ToDo

1. Add ability to override keyUsage/extendedKeyUsage when signing a new cert

## License

This project is free software licensed under the [GPLv3](http://www.gnu.org/licenses/gpl.txt).
