################################
Certificate authority management
################################

The only way to create and manage certificate authorities is via the command
line. It is obviously most important that the private keys of the certificate
authorities are never exposed to any attacker, and any web interface would pose
an unnecessary risk.

For the same reason, the private key of a certificate authority is stored on the
filesystem and not in the database. The initial location of the private key is
configured by the :ref:`CA_DIR setting <settings-ca-dir>`. This also means that
you can run your **django-ca** on two hosts, where one host has the private key
and only uses the command line, and one with the webinterface that can still be
used to revoke certificates.
