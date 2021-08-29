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
#
# Wrapper-script for dnsmasq to automatically restart it if the configuration changes.
#
# dnsmasq only supports auto-reloading hosts files, but these can only be used for A/AAAA records. TXT records
# (and SRV, MX, ... records) can only be set in the main configuration files. Sending SIGHUP also does *not*
# reload the configuration.
#
# DNS-01 ACME challenges work by adding a TXT record to the requested domain. The certbot hook script writes
# the configuration to $DNSMASQ_CONF_DIR (set in the Dockerfile) and this script will take care of restarting
# dnsmasq.
#
# NOTE: inotify only works inside a Docker container if the watched directory is a bind mount.

while true; do
    dnsmasq --no-daemon --conf-dir=$DNSMASQ_CONF_DIR,*.conf "$@" &
    PID=$!

	# Wait for configuration changes.
	# WARNING: $DNSMASQ_CONF_DIR must be a bind mount for this to work!
    inotifywait -e modify -e move -e create -e delete -e attrib -r $DNSMASQ_CONF_DIR

    kill $PID
done

