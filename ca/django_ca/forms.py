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

from django import forms
from django.utils.translation import ugettext_lazy as _

from .fields import BasicConstraintsField
from .models import Certificate


class CreateCertificateForm(forms.ModelForm):
    subjectAltName = forms.CharField(label='subjectAltName', required=False)
    keyUsage = forms.CharField(label='keyUsage', required=False)
    extendedKeyUsage = forms.CharField(label='extendedKeyUsage', required=False)
    basicConstraints = BasicConstraintsField(label='basicConstraints')

    class Meta:
        model = Certificate
        fields = ['cn', 'csr', 'watchers', ]


class RevokeCertificateForm(forms.ModelForm):
    reason = forms.ChoiceField(required=False, choices=(
        ('', _('No reason')),
        ('unspecified', _('Unspecified')),
        ('keyCompromise', _('Key compromised')),
        ('CACompromise', _('CA compromised')),
        ('affiliationChanged', _('Affiliation changed')),
        ('superseded', _('Superseded')),
        ('cessationOfOperation', _('Cessation of operation')),
        ('certificateHold', _('On Hold')),
        # Not currently useful according to "man ca":
        #('removeFromCRL', _('Remove from CRL')),
    ))

    class Meta:
        model = Certificate
        fields = []
