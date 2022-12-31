# PyOpenSSL 22.1.0 does have some type hints, but is missing a py.typed file. The file is not yet wanted:
#    https://github.com/pyca/pyopenssl/pull/1136
#
# There is types-PyOpenSSL, but it depends on a very old types-cryptography, so that breaks mypy even further.
