# -*- coding: utf-8 -*-
#
# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca.  If not,
# see <http://www.gnu.org/licenses/>.

import binascii

import six

from cryptography import x509
from cryptography.x509 import TLSFeatureType
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import ObjectIdentifier


@six.python_2_unicode_compatible
class Extension(object):
    """Convenience class to handle X509 Extensions.

    The constructor accepts multiple types for the ``value`` parameter, so that it can be used in most
    situations, it can be one of:

    * subclass of :py:class:`~cryptography:cryptography.x509.ExtensionType`
    * list/tuple, in which case the *first* value is assumed to be a
      boolean value denoting if the extension is ``critical``.
    * str, in which case the extension is parsed

    Parameters
    ----------

    value
        The value of the extension.
    """

    def __init__(self, value):
        if isinstance(value, x509.extensions.Extension):  # e.g. from a cert object
            self.critical = value.critical
            self._from_extension(value)
        elif isinstance(value, (list, tuple)):  # e.g. from a form
            self._from_list(*value)
            self._test_value()
        elif isinstance(value, dict):  # e.g. from settings
            self._from_dict(value)
            self._test_value()
        elif isinstance(value, six.string_types):  # e.g. from commandline parser
            self._from_str(value)
            self._test_value()
        else:
            raise ValueError('Value is of unsupported type %s' % type(value))
        if not isinstance(self.critical, bool):
            raise ValueError('%s: Invalid critical value passed.' % self.critical)

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical and self.value == other.value

    def __repr__(self):
        return str(self)

    def __str__(self):
        return '<%s: %s, critical=%s>' % (self.__class__.__name__, self.value, self.critical)

    def _from_str(self, value):
        if value.startswith('critical,'):
            self.critical = True
            self.value = value[9:]
        else:
            self.critical = False
            self.value = value

    def _from_dict(self, value):
        self.critical = value.get('critical', False)
        self.value = value['value']

    def _from_list(self, critical, value):
        self.critical = critical
        self.value = value

    def _test_value(self):
        pass

    @property
    def _text_header(self):
        if self.critical:
            return '%s (critical):' % self.oid._name
        else:
            return '%s:' % self.oid._name

    def add_colons(self, s):
        return ':'.join([s[i:i + 2] for i in range(0, len(s), 2)])

    @property
    def _text_value(self):
        return self.value

    def as_extension(self):
        return x509.extensions.Extension(oid=self.oid, critical=self.critical, value=self.extension_type)

    @property
    def as_text(self):
        return '%s\n    %s' % (self._text_header, self._text_value)

    def for_builder(self):
        return {'extension': self.extension_type, 'critical': self.critical}


class MultiValueExtension(Extension):
    """A generic base class for extensions that have multiple values.

    """
    KNOWN_VALUES = set()

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.critical == other.critical \
            and sorted(self.value) == sorted(other.value)

    def __str__(self):
        return '<%s: %s, critical=%s>' % (self.__class__.__name__, sorted(self.value), self.critical)

    def _from_dict(self, value):
        self.critical = value.get('critical', False)
        self.value = value['value']
        if isinstance(self.value, six.string_types):
            self.value = [self.value]

    def _from_str(self, value):
        super(MultiValueExtension, self)._from_str(value)
        self.value = [v.strip() for v in self.value.split(',') if v.strip()]

    def __contains__(self, value):
        return value in self.value

    def __len__(self):
        return len(self.value)

    def _test_value(self):
        diff = set(self.value) - self.KNOWN_VALUES
        if diff:
            raise ValueError('Unknown value(s): %s' % ', '.join(sorted(diff)))

    @property
    def _text_value(self):
        # note: we strip here because as_text() already appends the first four spaces
        return '\n'.join(['    * %s' % v for v in sorted(self.value)]).strip()

    def form_decompress(self):
        return self.value, self.critical


class KeyIdExtension(Extension):
    def __str__(self):
        return '<%s: %s>' % (self.__class__.__name__, self._text_value)

    @property
    def _text_value(self):
        return self.add_colons(binascii.hexlify(self.value).upper().decode('utf-8'))


class KeyUsage(MultiValueExtension):
    oid = ExtensionOID.KEY_USAGE
    CRYPTOGRAPHY_MAPPING = {
        'cRLSign': 'crl_sign',
        'dataEncipherment': 'data_encipherment',
        'decipherOnly': 'decipher_only',
        'digitalSignature': 'digital_signature',
        'encipherOnly': 'encipher_only',
        'keyAgreement': 'key_agreement',
        'keyCertSign': 'key_cert_sign',
        'keyEncipherment': 'key_encipherment',
        'nonRepudiation': 'content_commitment',  # http://marc.info/?t=107176106300005&r=1&w=2
    }
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING)

    CHOICES = (
        ('cRLSign', 'CRL Sign'),
        ('dataEncipherment', 'dataEncipherment'),
        ('decipherOnly', 'decipherOnly'),
        ('digitalSignature', 'Digital Signature'),
        ('encipherOnly', 'encipherOnly'),
        ('keyAgreement', 'Key Agreement'),
        ('keyCertSign', 'Certificate Sign'),
        ('keyEncipherment', 'Key Encipherment'),
        ('nonRepudiation', 'nonRepudiation'),
    )

    def _from_extension(self, ext):
        self.value = []
        for k, v in self.CRYPTOGRAPHY_MAPPING.items():
            try:
                if getattr(ext.value, v):
                    self.value.append(k)
            except ValueError:
                # cryptography throws a ValueError if encipher_only/decipher_only is accessed and
                # key_agreement is not set.
                pass

    @property
    def extension_type(self):
        kwargs = {v: (k in self.value) for k, v in self.CRYPTOGRAPHY_MAPPING.items()}
        if kwargs['decipher_only']:
            kwargs['key_agreement'] = True
        return x509.KeyUsage(**kwargs)


class ExtendedKeyUsage(MultiValueExtension):
    oid = ExtensionOID.EXTENDED_KEY_USAGE
    CRYPTOGRAPHY_MAPPING = {
        'serverAuth': ExtendedKeyUsageOID.SERVER_AUTH,
        'clientAuth': ExtendedKeyUsageOID.CLIENT_AUTH,
        'codeSigning': ExtendedKeyUsageOID.CODE_SIGNING,
        'emailProtection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
        'timeStamping': ExtendedKeyUsageOID.TIME_STAMPING,
        'OCSPSigning': ExtendedKeyUsageOID.OCSP_SIGNING,
        'smartcardLogon': ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),
        'msKDC': ObjectIdentifier("1.3.6.1.5.2.3.5"),
    }
    _CRYPTOGRAPHY_MAPPING_REVERSED = {v: k for k, v in CRYPTOGRAPHY_MAPPING.items()}
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING)
    CHOICES = (
        ('serverAuth', 'SSL/TLS Web Server Authentication'),
        ('clientAuth', 'SSL/TLS Web Client Authentication'),
        ('codeSigning', 'Code signing'),
        ('emailProtection', 'E-mail Protection (S/MIME)'),
        ('timeStamping', 'Trusted Timestamping'),
        ('OCSPSigning', 'OCSP Signing'),
        ('smartcardLogon', 'Smart card logon'),
        ('msKDC', 'Kerberos Domain Controller'),
    )

    def _from_extension(self, ext):
        self.value = [self._CRYPTOGRAPHY_MAPPING_REVERSED[u] for u in ext.value]

    @property
    def extension_type(self):
        return x509.ExtendedKeyUsage([self.CRYPTOGRAPHY_MAPPING[u] for u in self.value])


class SubjectKeyIdentifier(KeyIdExtension):
    oid = ExtensionOID.SUBJECT_KEY_IDENTIFIER

    def _from_extension(self, ext):
        self.value = ext.value.digest


class AuthorityKeyIdentifier(KeyIdExtension):
    oid = ExtensionOID.AUTHORITY_KEY_IDENTIFIER

    def _from_extension(self, ext):
        self.value = ext.value.key_identifier

    @property
    def _text_value(self):
        return 'keyid:%s' % super(AuthorityKeyIdentifier, self)._text_value


class TLSFeature(MultiValueExtension):
    oid = ExtensionOID.TLS_FEATURE
    CHOICES = (
        ('OCSPMustStaple', 'OCSP Must-Staple'),
        ('MultipleCertStatusRequest', 'Multiple Certificate Status Request'),
    )
    CRYPTOGRAPHY_MAPPING = {
        # https://tools.ietf.org/html/rfc6066.html:
        'OCSPMustStaple': TLSFeatureType.status_request,
        # https://tools.ietf.org/html/rfc6961.html (not commonly used):
        'MultipleCertStatusRequest': TLSFeatureType.status_request_v2,
    }
    _CRYPTOGRAPHY_MAPPING_REVERSED = {v: k for k, v in CRYPTOGRAPHY_MAPPING.items()}
    KNOWN_VALUES = set(CRYPTOGRAPHY_MAPPING)

    def _from_extension(self, ext):
        self.value = [self._CRYPTOGRAPHY_MAPPING_REVERSED[f] for f in ext.value]

    @property
    def extension_type(self):
        return x509.TLSFeature([self.CRYPTOGRAPHY_MAPPING[f] for f in self.value])
