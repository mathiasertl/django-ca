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

from fabric.api import env
from fabric.api import local
from fabric.api import task
from fabric.colors import green
from fabric.colors import red
from fabric.context_managers import cd
from fabric.context_managers import hide
from fabric.context_managers import settings
from fabric.decorators import runs_once
from fabric.utils import abort

from six.moves import configparser

config = configparser.ConfigParser({
    'app': 'False',
    'app-collectstatic': 'True',
    'app-database': '',
    'app-migrate': 'True',
    'app-origin': 'git+https://github.com/mathiasertl/django-ca.git#egg=django-ca',
    'app-project-dir': '%(app-venv)s',
    'app-uwsgi-vassal': '',
    'branch': 'master',
    'project': 'False',
    'project-collectstatic': 'True',
    'project-database': '',
    'project-git': '%(project-venv)s',
    'project-migrate': 'True',
    'project-uwsgi-vassal': '',
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


@task
def livehtml(port=8001):
    local('make -C docs clean')
    local('sphinx-autobuild docs/source docs/build/html -p %s -z ca '
          '-i *.swp -i *.swo -i *.swx -i *~ -i *4913' % port)


@task
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

        if config.get(section, 'app-uwsgi-vassal'):
            sudo('touch %s' % config.get(section, 'app-uwsgi-vassal'))


@task
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

        if config.get(section, 'project-uwsgi-vassal'):
            sudo('touch %s' % config.get(section, 'project-uwsgi-vassal'))


@task
def deploy(section='DEFAULT'):
    deploy_project(section=section)
    deploy_app(section=section)


def create_cert(name, **kwargs):
    from django.core.management import call_command as manage
    from django_ca import ca_settings

    key = os.path.join(ca_settings.CA_DIR, '%s.key' % name)
    csr = os.path.join(ca_settings.CA_DIR, '%s.csr' % name)
    pem = os.path.join(ca_settings.CA_DIR, '%s.pem' % name)
    kwargs.setdefault('subject', {})
    kwargs['subject'].setdefault('CN', name)

    with hide('everything'):
        local('openssl genrsa -out %s 2048' % key)
        local("openssl req -new -key %s -out %s -utf8 -batch" % (key, csr))
    manage('sign_cert', csr=csr, out=pem, **kwargs)
    return key, csr, pem


@task
def init_demo(fixture='n'):
    fixture = fixture == 'y'
    # setup environment
    os.chdir('ca')
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ca.settings")
    sys.path.insert(0, os.getcwd())

    # setup django
    import django
    django.setup()

    # finally - imports!
    from django.conf import settings
    from django.contrib.auth import get_user_model
    from django.core.management import call_command as manage
    from django_ca import ca_settings
    from django_ca.models import Certificate
    from django_ca.models import CertificateAuthority
    from django_ca.models import Watcher
    User = get_user_model()

    if settings.DEBUG is not True:
        abort(red('Refusing to run if settings.DEBUG != True.'))

    if os.path.exists(os.path.join('ca', 'db.sqlite3')):
        abort(red('CA already set up.'))

    print(green('Creating database...'))
    manage('migrate', verbosity=0)
    print(green('Initiating CA...'))
    manage('init_ca', 'Root CA', '/C=AT/ST=Vienna/L=Vienna/O=example/OU=example/CN=ca.example.com',
           pathlen=1, ocsp_url='http://ocsp.ca.example.com', crl_url=['http://localhost/certs.crl'],
           issuer_url='http://ca.example.com/ca.crt', issuer_alt_name='https://ca.example.com'
           )
    root_ca = CertificateAuthority.objects.get(name='Root CA')

    print(green('Initiating Child CA...'))
    manage(
        'init_ca', 'Child CA', '/C=AT/ST=Vienna/L=Vienna/O=example/OU=example/CN=sub.ca.example.com',
        parent=root_ca, ca_crl_url='http://localhost/ca.crl',
    )
    child_ca = CertificateAuthority.objects.get(name='Child CA')

    # generate OCSP certificate
    print(green('Generate OCSP certificate...'))
    ocsp_key, ocsp_csr, ocsp_pem = create_cert('localhost', alt=['localhost'], profile='ocsp')

    # Create some client certificates (always trust localhost to ease testing)
    for i in range(1, 10):
        hostname = 'host%s.example.com' % i
        print(green('Generate certificate for %s...' % hostname))
        if fixture:
            create_cert(hostname)
        else:
            create_cert(hostname, alt=['localhost'])

    # create stunnel.pem
    key_path = os.path.join(ca_settings.CA_DIR, 'host1.example.com.key')
    pem_path = os.path.join(ca_settings.CA_DIR, 'host1.example.com.pem')
    stunnel_path = os.path.join(ca_settings.CA_DIR, 'stunnel.pem')
    with open(key_path) as key, open(pem_path) as pem, open(stunnel_path, 'w') as stunnel:
        stunnel.write(key.read())
        stunnel.write(pem.read())

    print(green('Creating client certificate...'))
    create_cert('client', subject={'CN': 'First Last'}, cn_in_san=False, alt=['user@example.com'],
                ca=child_ca)

    # Revoke host1 and host2
    if not fixture:
        print(green('Revoke host1.example.com and host2.example.com...'))
        cert = Certificate.objects.get(cn='host1.example.com')
        cert.revoke()
        cert.save()

        cert = Certificate.objects.get(cn='host2.example.com')
        cert.revoke('key_compromise')
        cert.save()

    print(green('Create CRL and OCSP index...'))
    crl_path = os.path.join(ca_settings.CA_DIR, 'crl.pem')
    ocsp_index = os.path.join(ca_settings.CA_DIR, 'ocsp_index.txt')
    manage('dump_crl', crl_path)
    manage('dump_ocsp_index', ocsp_index, ca=root_ca)

    ca_crl_path = os.path.join(ca_settings.CA_DIR, 'ca_crl.pem')

    # Concat the CA certificate and the CRL, this is required by "openssl verify"
    with open(crl_path) as crl, open(ca_crl_path, 'w') as ca_crl:
        ca_crl.write(root_ca.pub)
        ca_crl.write(crl.read())

    # create a few watchers
    Watcher.from_addr('First Last <user1@example.com>')
    Watcher.from_addr('Second Last <user2@example.com>')

    # create admin user for login
    User.objects.create_superuser('user', 'user@example.com', 'nopass')

    # write public ca cert so it can be used by demo commands below
    ca_crt = os.path.join(ca_settings.CA_DIR, '%s.pem' % root_ca.serial)
    with open(ca_crt, 'w') as outstream:
        outstream.write(root_ca.pub)
    ca_crt = os.path.join(ca_settings.CA_DIR, '%s.pem' % child_ca.serial)
    with open(ca_crt, 'w') as outstream:
        outstream.write(child_ca.pub)

    os.chdir('../')
    cwd = os.getcwd()
    rel = lambda p: os.path.relpath(p, cwd)  # NOQA
    ca_crt = rel(ca_crt)
    host1_pem = rel(os.path.join(ca_settings.CA_DIR, 'host1.example.com.pem'))
    print("")
    print(green('* All certificates are in %s' % rel(ca_settings.CA_DIR)))
    print(green('* Verify with CRL:'))
    print('\topenssl verify -CAfile %s -crl_check %s' % (rel(ca_crl_path), rel(host1_pem)))
    print(green('* Run OCSP responder:'))
    print('\topenssl ocsp -index %s -port 8888 -rsigner %s -rkey %s -CA %s -text' %
          (rel(ocsp_index), rel(ocsp_pem), rel(ocsp_key), ca_crt))
    print(green('* Verify certificate with OCSP:'))
    print('\topenssl ocsp -CAfile %s -issuer %s -cert %s -url http://localhost:8888 -resp_text' %
          (ca_crt, ca_crt, host1_pem))
    print(green('* Start webserver on http://localhost:8000 (user: user, password: nopass) with:'))
    print('\tpython ca/manage.py runserver')
