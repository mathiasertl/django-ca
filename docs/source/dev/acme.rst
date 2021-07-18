################
ACME development
################

*********
Standards
*********

* `RFC 8555: ACMEv2 <https://tools.ietf.org/html/rfc8555>`_
* `RFC 7515: JSON Web Signature (JWS) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7517: JSON Web Key (JWK) <https://tools.ietf.org/html/rfc7515>`_
* `RFC 7638: JSON Web Key (JWK) Thumbprint <https://tools.ietf.org/html/rfc7638>`_

***************
Tips and tricks
***************

Query LE::

   $ curl -v https://acme-v02.api.letsencrypt.org/directory

Use local server::

   $ certbot register --agree-tos -m user@localhost \
   >    --config-dir=.certbot/config/ --work-dir=.certbot/work/ --logs-dir=.certbot/logs \
   >    --server http://localhost:8000/django_ca/acme/directory/

   $ certbot certonly --standalone \
   >    --config-dir=.certbot/config/ --work-dir=.certbot/work/ --logs-dir=.certbot/logs \
   >    --server http://localhost:8000/django_ca/acme/directory/ \
   >    -d test.example.com


base64url encoding
==================

The ACME library does that with `josepy <https://pypi.org/project/josepy/>`_ (which is **not** the
similar/forked? `python-jose <https://pypi.org/project/python-jose/>`_):

.. code-block:: python3

   >>> import josepy as jose
   >>> jose.b64encode(b'test')
   b'dGVzdA'
   >>> jose.b64decode(b'dGVzdA')
   b'test'
