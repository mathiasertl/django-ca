## ChangeLog

### 1.0.0

* Move this project from https://github.com/fsinf/certificate-authority to
  https://github.com/mathiasertl/django-ca.
* This version now absolutely assumes Python3. Python2 is no longer supported.
* The main app was renamed from `certificate` to `django_ca`. See below for how to upgrade.
* Include a setup.py file so the project can be installed via pip.
* `manage.py` commands are now renamed to be more specific:
  * `init` -> `init_ca`
  * `sign` -> `sign_cert`
  * `list` -> `list_ca`
  * `revoke` -> `revoke_cert`
  * `crl` -> `dump_crl`
  * `view` -> `view_cert`
  * `watch` -> `notify_expiring_certs`
  * `watchers` -> `cert_watchers`
* New command `dump_cert` to dump certificates to a file.
* New command `dump_ocsp_index` for an OCSP responder, `dump_crl` no longer outputs this file.
* Removed the `manage.py remove` command.
* Update Django dependency to 1.9.

#### Update from versions prior to 1.0.0

Prior to 1.0.0, this app was not intended to be reusable and so had a generic name. The app was
renamed to `django_ca`, so it can be used in other Django projects (or hopefully stand-alone,
someday). Essentially, the upgrade path should work something like this:

```
# backup old data:
python manage.py dumpdata certificate --indent=4 > certs.json

# update source code
git pull origin master

# create initial models in the new app, but only the initial version!
python manage.py migrate django_ca 0001

# update JSON with new model name
sed 's/"certificate.certificate"/"django_ca.certificate"/' > certs-updated.json

# load data
python manage.py loaddata certs-updated.json

# apply any other migrations
python manage.py migrate
```

### 0.2.1 (2015-05-24)

* Signed certificates are valid five minutes in the past to account for possible clock skew.
* Shell-scripts: Correctly pass quoted parameters to manage.py.
* Add documentation on how to test CRLs.
* Improve support for OCSP.

### 0.2 (2015-02-08)

* The ``watchers`` command now takes a serial, like any other command.
* Reworked ``view`` command for more robustness.
  * Improve output of certificate extensions.
  * Add the ``-n``/``--no-pem`` option.
  * Add the ``-e``/``--extensions`` option to print all certificate extensions.
  * Make output clearer.
* The ``sign`` command now has
  * a ``--key-usage`` option to override the ``keyUsage`` extended attribute.
  * a ``--ext-key-usage`` option to override the ``extendedKeyUsage`` extended attribute.
  * a ``--ocsp`` option to sign a certificate for an OCSP server.
* The default ``extendedKeyUsage`` is now ``serverAuth``, not ``clientAuth``.
* Update the remove command to take a serial.
* Ensure restrictive file permissions when creating a CA.
* Add requirements-dev.txt

### 0.1 (2015-02-07)

* Initial release
