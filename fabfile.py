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
import sys

from six.moves import configparser

from fabric.api import env
from fabric.api import local
from fabric.colors import green
from fabric.colors import red
from fabric.context_managers import cd
from fabric.context_managers import hide
from fabric.context_managers import settings
from fabric.decorators import runs_once
from fabric.utils import abort

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
    # setup environment
    os.chdir('ca')
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.settings")
    sys.path.insert(0, os.getcwd())

    # setup django
    import django
    django.setup()

    # finally - imports!
    from django.conf import settings
    from django.core.management import call_command as manage
    from django_ca.models import Certificate

    if settings.DEBUG is not True:
        abort(red('Refusing to run if settings.DEBUG != True.'))

    if os.path.exists(settings.CA_KEY) or os.path.exists(settings.CA_CRT):
        abort(red('CA already set up.'))

    print(green('Creating database...'))
    manage('migrate', verbosity=0)
    print(green('Initiating CA...'))
    manage('init_ca', 'AT', 'Vienna', 'Vienna', 'example', 'example',
           'ca.example.com')

    # generate OCSP certificate
    print(green('Generate OCSP certificate...'))
    ocsp_key = os.path.join(settings.CA_DIR, 'localhost.key')
    ocsp_csr = os.path.join(settings.CA_DIR, 'localhost.csr')
    ocsp_pem = os.path.join(settings.CA_DIR, 'localhost.pem')
    with hide('everything'):
        local('openssl genrsa -out files/localhost.key 2048')
        local("openssl req -new -key %s -out %s -utf8 -sha512 -batch -subj '/C=AT/ST=Vienna/L=Vienna/CN=localhost/'" % (ocsp_key, ocsp_csr))
    manage('sign_cert', csr=ocsp_csr, out=ocsp_pem, ocsp=True)

    # Create some client certificates
    for name in ['host1', 'host2', 'host3', 'host4']:
        hostname = '%s.example.com' % name
        print(green('Generate certificate for %s...' % hostname))
        key = 'files/%s.key' % hostname
        csr = 'files/%s.csr' % hostname
        subj = '/C=AT/ST=Vienna/L=Vienna/CN=%s/' % hostname

        with hide('everything'):
            local('openssl genrsa -out %s 2048' % key)
            local("openssl req -new -key %s -out %s -utf8 -sha512 -batch -subj '%s'" % (
                key, csr, subj))
        manage('sign_cert', csr=csr, out='files/%s.pem' % hostname)

    # Revoke host1 and host2
    print(green('Revoke host1.example.com and host2.example.com...'))
    cert = Certificate.objects.get(cn='host1.example.com')
    cert.revoke()
    cert.save()

    cert = Certificate.objects.get(cn='host2.example.com')
    cert.revoke('keyCompromise')
    cert.save()

    print(green('Create CRL and OCSP index...'))
    crl_path = os.path.join(settings.CA_DIR, 'crl.pem')
    ocsp_index = os.path.join(settings.CA_DIR, 'ocsp_index.txt')
    manage('dump_crl', crl_path)
    manage('dump_ocsp_index', ocsp_index)

    ca_crl_path = os.path.join(settings.CA_DIR, 'ca_crl.pem')

    # Concat the CA certificate and the CRL, this is required by "openssl verify"
    with open(crl_path) as crl, open(settings.CA_CRT) as ca_pem, open(ca_crl_path, 'w') as ca_crl:
        ca_crl.write(ca_pem.read())
        ca_crl.write(crl.read())

    os.chdir('../')
    cwd = os.getcwd()
    rel = lambda p: os.path.relpath(p, cwd)
    ca_crt = rel(settings.CA_CRT)
    host1_pem = rel(os.path.join(settings.CA_DIR, 'host1.example.com.pem'))
    print("")
    print(green('* All certificates are in %s' % rel(settings.CA_KEY)))
    print(green('* Verify with CRL:'))
    print('\topenssl verify -CAfile %s -crl_check %s' % (rel(ca_crl_path), rel(host1_pem)))
    print(green('* Run OCSP responder:'))
    print('\topenssl ocsp -index %s -port 8888 -rsigner %s -rkey %s -CA %s -text' % (rel(ocsp_index), rel(ocsp_pem), rel(ocsp_key), ca_crt))
    print(green('* Verify certificate with OCSP:'))
    print('\topenssl ocsp -CAfile %s -issuer %s -cert %s -url http://localhost:8888 -resp_text' % (ca_crt, ca_crt, host1_pem))
