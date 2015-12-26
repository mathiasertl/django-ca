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

import os

from six.moves import configparser

from fabric.api import local
from fabric.api import env
from fabric.context_managers import settings
from fabric.context_managers import cd
from fabric.decorators import runs_once


config = configparser.ConfigParser({
    'app': 'False',
    'app-collectstatic': 'True',
    'app-database': '',
    'app-migrate': 'True',
    'app-origin': 'git+https://github.com/mathiasertl/django-ca.git#egg=django-ca',
    'app-project-dir': '%(app-venv)s',
    'branch': 'master',
    'project': 'False',
    'project-collectstatic': 'True',
    'project-database': '',
    'project-git': '%(project-venv)s',
    'project-migrate': 'True',
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
    if remote:
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

        if config.getboolean(section, 'app-collectstatic'):
            sudo('%s collectstatic --noinput' % manage)


def deploy_project(section='DEFAULT'):
    if not config.getboolean(section, 'project'):
        return
    push(section)

    venv = config.get(section, 'project-venv')
    gitdir = config.get(section, 'project-git')
    pip = os.path.join(venv, 'bin', 'pip')
    python = os.path.join(venv, 'bin', 'python')
    manage = '%s %s' % (python, os.path.join(gitdir, 'ca', 'manage.py'))
    with settings(host=config.get(section, 'project-host')):
        with cd(gitdir):
            sudo('git pull origin master')
            sudo('%s install -U -r requirements.txt' % pip)

        if config.getboolean(section, 'project-migrate'):
            database = config.get(section, 'project-database')

            command = '%s migrate --noinput' % manage
            if database:
                command += ' --database=%s' % database
            sudo(command)

        if config.getboolean(section, 'project-collectstatic'):
            sudo('%s collectstatic --noinput' % manage)

def deploy(section='DEFAULT'):
    deploy_project(section=section)
    deploy_app(section=section)


def init_demo():
    os.chdir('ca')

    # create db
    local('python manage.py migrate')

    # init CA
    local('python manage.py init_ca AT example example example example ca.example.com')

    # generate OCSP certificate
    local('openssl genrsa -out files/localhost.key 4096')  # for OCSP service
    local("openssl req -new -key files/localhost.key -out files/localhost.csr -utf8 -sha512 -batch -subj '/C=AT/ST=Vienna/L=Vienna/CN=localhost/'""")
    local('python manage.py sign_cert --csr files/localhost.csr --out files/localhost.crt --ocsp')

    for name in ['host1', 'host2', 'host3', 'host4']:
        hostname = '%s.example.com' % name
        key = 'files/%s.key' % hostname
        csr = 'files/%s.csr' % hostname
        pem = 'files/%s.pem' % hostname
        subj = '/C=AT/ST=Vienna/L=Vienna/CN=%s/' % hostname

        local('openssl genrsa -out %s 2048' % key)
        local("openssl req -new -key %s -out %s -utf8 -sha512 -batch -subj 'subj'" % (
            key, csr, subj))
        local('python manage.py sign_cert --csr %s --out %s' % (csr, pem))
