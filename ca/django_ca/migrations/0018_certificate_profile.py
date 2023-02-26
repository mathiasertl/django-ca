# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

# Generated by Django 3.0.2 on 2020-01-19 11:27

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("django_ca", "0017_auto_20200112_1657"),
    ]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="profile",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Profile that was used to generate this certificate.",
                max_length=32,
            ),
        ),
    ]
