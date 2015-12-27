#!/usr/bin/env python3

from distutils.core import setup


setup(
    name='django-ca',
    version='1.0.0b1',
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
    zip_safe=False,  # because of the static files
    install_requires=[
        'Django>=1.9',
        'pyOpenSSL>=0.15',
    ],
    classifiers=[
        'Framework :: Django',
        'Framework :: Django :: 1.9',
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
