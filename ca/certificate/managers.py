import uuid

from datetime import datetime
from datetime import timedelta

from OpenSSL import crypto

from django.conf import settings
from django.db import models

DIGEST_ALGORITHM = getattr(settings, 'DIGEST_ALGORITHM', 'sha512')


class CertificateManager(models.Manager):

    def from_csr(self, csr, subjectAltNames=None, days=730, algorithm=None,
                 watchers=None):
        # get algorithm used to sign certificate
        if algorithm is None:
            algorithm = DIGEST_ALGORITHM

        # get certificate information
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
        subject = req.get_subject()
        cn = dict(subject.get_components())['CN']

        # get issuer cert:
        issuerKey = crypto.load_privatekey(
            crypto.FILETYPE_PEM, open(settings.CA_PRIVATE_KEY).read())
        issuerPub = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(settings.CA_PUBLIC_KEY).read())

        # compute notAfter info
        expires = datetime.today() + timedelta(days=days + 1)
        expires = expires.replace(hour=0, minute=0, second=0, microsecond=0)

        # create signed certificate
        cert = crypto.X509()
        cert.set_serial_number(uuid.uuid4().int)
        cert.set_notBefore(datetime.utcnow().strftime('%Y%m%d%H%M%SZ'))
        cert.set_notAfter(expires.strftime('%Y%m%d%H%M%SZ'))
        cert.set_issuer(issuerPub.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())

        # collect any extension
        extensions = []

        # add subjectAltName if given:
        if subjectAltNames:
            subjData = ','.join(['DNS:%s' % n for n in subjectAltNames])
            ext = crypto.X509Extension('subjectAltName', 0, subjData)
            extensions.append(ext)

        cert.add_extensions(extensions)

        # finally sign the certificate:
        cert.sign(issuerKey, algorithm)

        # create database object
        obj = self.create(
            csr=csr,
            pub=crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
            cn=cn,
            expires=expires,
        )

        # add watchers:
        if watchers:
            obj.watchers.add(*watchers)

        return obj
