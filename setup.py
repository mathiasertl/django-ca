#!/usr/bin/env python3

from setuptools import find_packages
from setuptools import setup
from pkg_resources import resource_string


requirements = resource_string(__name__, 'requirements.txt').decode('utf-8').splitlines()
requirements = [r.replace('==', '>=') for r in requirements]

setup(
    name='django-ca',
    version='1.0.0b1',
    description='',
    author='Mathias Ertl',
    author_email='mati@er.tl',
    url='https://github.com/mathiasertl/django-ca',
    packages=find_packages('ca', exclude=['ca']),
    package_dir={'django_ca': 'ca/django_ca'},
    zip_safe=False,  # because of the static files
    install_requires=requirements,
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
