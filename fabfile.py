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
    'app': 'False',
    'app-database': '',
    'app-migrate': 'True',
    'app-origin': 'git+https://github.com/mathiasertl/django-ca.git#egg=django-ca',
    'app-project-dir': '%(app-venv)s',
    'branch': 'master',
    'project': 'False',
    'project-database': '',
    'project-git': '%(project-venv)s',
    'project-migrate': 'False',
    'remote': 'origin',
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
    if not config.getboolean(section, 'app'):
        return
    push(section)

    venv = config.get(section, 'app-venv')
    pip = os.path.join(venv, 'bin', 'pip')
    python = os.path.join(venv, 'bin', 'python')
    project_dir = config.get(section, 'app-project-dir')
    manage = '%s %s' % (python, os.path.join(project_dir, 'manage.py'))

    with settings(host=config.get(section, 'app-host')):
        sudo('%s install -e %s' % (pip, config.get(section, 'app-origin')))

        if config.getboolean(section, 'app-migrate'):
            database = config.get(section, 'app-database')

            command = '%s migrate --noinput' % manage
            if database:
                command += ' --database=%s' % database
            sudo(command)


def deploy_project(section='DEFAULT'):
    if not config.getboolean(section, 'project'):
        return
    push(section)

    venv = config.get(section, 'project-venv')
    gitdir = config.get(section, 'project-git')
    pip = os.path.join(venv, 'bin', 'pip')
    python = os.path.join(venv, 'bin', 'python')
    manage = '%s %s' % (python, os.path.join(gitdir, 'ca', 'manage.py'))
    with settings(host=config.get(section, 'project-host')), cd(gitdir):
        sudo('git pull origin master')
        sudo('%s install -U -r requirements.txt' % pip)

        if config.getboolean(section, 'project-migrate'):
            database = config.get(section, 'project-database')

            command = '%s migrate --noinput' % manage
            if database:
                command += ' --database=%s' % database
            sudo(command)

def deploy(section='DEFAULT'):
    deploy_project(section=section)
#    deploy_app(section=section)
