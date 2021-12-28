************
Requirements
************

This guide assumes that you have moderate knowledge of running servers, installing software and how TLS
certificates work.

We assume you have a dedicated server where you set up your certificate authority. The guide does not account
for potential conflicts with other software like ports, directories or container names.

Setup DNS
=========

*Before* you set up your certificate authority, you need a domain name that points to the server where you
install django-ca. Since the domain is encoded in CA certificates, it cannot be easily changed later.

This guide assumes that ``ca.example.com`` is the name that points to the server where you are setting up your
certificate authority.
