#!/bin/bash
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

# Small wrapper script for invoking certbot the right way

TYPE=$1
DOMAIN=$2
shift
shift

usage () {
    echo "$0 [dns|http] [domain] [certbot-args]...

Shortcut to request an ACMEv2 certificate in the local test setup via certbot.

This script takes a challenge type (http/dns) and a single domain. Any further args are passed to certbot.

Example:

	`basename $0` http http-01.example.com --verbose

See also:

	https://django-ca.readthedocs.io/en/latest/dev/acme.html
"
}

if [[ $TYPE == "dns" ]]; then
    set -ex
    certbot certonly --manual --preferred-challenges dns --manual-auth-hook django-ca-dns-auth --manual-cleanup-hook django-ca-dns-clean -d $DOMAIN "$@"
elif [[ $TYPE == "http" ]]; then
    set -ex
    certbot certonly --standalone --preferred-challenges http -d $DOMAIN "$@"
else
    usage
    exit 1
fi
