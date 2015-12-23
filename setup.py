#!/usr/bin/env python3

import os

from distutils.core import setup

my_path = os.path.normpath(os.path.abspath(__file__))
my_base = os.path.dirname(my_path)

dist_dir = os.path.join(my_base, 'dist')
template = os.path.join(my_base, 'MANIFEST.in')

os.chdir(os.path.join(my_base, 'ca'))

setup(
    name='django-ca',
    version='1.0.0',
    description='',
    author='Mathias Ertl',
    author_email='mati@er.tl',
    url='https://github.com/mathiasertl/django-ca',
    packages=[
        'django_ca',
        'django_ca.management',
        'django_ca.management.commands',
        'django_ca.migrations',
    ],
    install_requires=[
        'Django==1.9',
        'pyOpenSSL==0.15.1',
    ],
    classifiers=[
        'Framework :: Django',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    options={
        'sdist': {
            'dist_dir': dist_dir,
            'template': template,
        },
    }
)
