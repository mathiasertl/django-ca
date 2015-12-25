# -*- coding: utf-8 -*-
#
# This file is part of django-ca
# (https://github.com/mathiasertl/django-ca).
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

import os

from six.moves import configparser

from fabric.api import local
from fabric.api import env
from fabric.context_managers import settings
from fabric.context_managers import cd
from fabric.decorators import runs_once


config = configparser.ConfigParser({
    'remote': 'origin',
    'branch': 'master',
    'app-origin': 'git+https://github.com/mathiasertl/django-ca.git#egg=django-ca',
})
config.read('fab.conf')
env.use_ssh_config = True


def sudo(cmd):
    if env.cwd:
        local('ssh %s sudo sh -c \'"cd %s && %s"\'' % (env.host, env.cwd, cmd))
    else:
        local('ssh %s sudo %s' % (env.host, cmd))


@runs_once
def push(section):
    remote = config.get(section, 'remote')
    branch = config.get(section, 'branch')
    local('git push %s %s' % (remote, branch))


def deploy_app(section='DEFAULT'):
    push(section)

    venv = config.get(section, 'app-venv')
    pip = os.path.join(venv, 'bin', 'pip')
    with settings(host=config.get(section, 'app-host')):
        sudo('%s install -e %s' % (pip, config.get(section, 'app-origin')))


def deploy_project(section='DEFAULT'):
    push(section)


def deploy(section='DEFAULT'):
    deploy_project(section=section)
#    deploy_app(section=section)
