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

from django.views.generic.edit import UpdateView
from django.core.urlresolvers import reverse

from .forms import RevokeCertificateForm
from .models import Certificate


class RevokeCertificateView(UpdateView):
    admin_site = None
    model = Certificate
    form_class = RevokeCertificateForm
    template_name_suffix = '_revoke_form'
    template_name = 'django_ca/admin/certificate_revoke_form.html'

    def get_context_data(self, **kwargs):
        context = super(RevokeCertificateView, self).get_context_data(**kwargs)
        context.update(self.admin_site.each_context(self.request))
        return context

    def get_success_url(self):
        meta = self.model._meta
        return reverse('admin:%s_%s_change' % (meta.app_label, meta.verbose_name),
                       args=(self.object.pk, ))
