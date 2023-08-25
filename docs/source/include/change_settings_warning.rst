.. WARNING::

   If you change this settings, OCSP and CRL URLs encoded in existing certificates and intermediate CAs become
   invalid, so certificate validation using these URLs will fail. Also, ACMEv2 URLs will change, so every
   ACMEv2 client has to be updated.

   If you do change this setting after creating any certificates, you have to either start with a completely
   fresh set of certificates or make sure that the old URLs continue to work (e.g. by providing your own
   NGINX configuration).
