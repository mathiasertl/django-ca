#!/usr/bin/env python3

from distutils.core import setup

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
    package_dir={'': 'ca'},
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
)
