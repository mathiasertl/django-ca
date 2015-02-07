# fsinf-certificate-authority

This simple project allows you to manage a local TLS certificate authority from the command line.

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
openssl req -new -key example.com.key -out example.com.csr -utf8 -batch -sha512
```

### Sign a private key

Copy the CSR and sign it:

```
python ca/manage.py sign --csr example.com.csr --out example.com.crt
```

Note that the ``sign`` command has a few useful options, try the ``-h`` parameter for options.

### List certificates/View certificate

### Send warning emails on expired certificates

To notify admins about expiring certificates, use the ``manage.py watch`` command. Who will receive
notifications is configured either at signing time using the ``--watch`` parameter or using the
``manage.py watchers`` command (see below).

It is recommended you execute this job daily via cron:

```
# assuming you cloned the repo at /root/:
HOME=/root/certificate-authority
PATH=/root/certificate-authority/bin

# m h  dom mon dow     user           command
* 8    * * *           xmpp-account   python ca/manage.py watch
```

### Add/Remove watchers to certificates

## License

This project is free software licensed under the [GPLv3](http://www.gnu.org/licenses/gpl.txt).
