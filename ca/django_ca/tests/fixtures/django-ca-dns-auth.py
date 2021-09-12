#!/usr/bin/env python3
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

"""Authentication script for ACMEv2 dns-01 challenges.

.. see-also:: https://certbot.eff.org/docs/using.html#hooks
"""

import os
import time

print("certbot env variables:")
for key, value in [(k, v) for k, v in os.environ.items() if k.startswith("CERTBOT_")]:
    print(key, "-->", value)

domain = "_acme_challenge.%s" % os.environ["CERTBOT_DOMAIN"]
validation = os.environ["CERTBOT_VALIDATION"]
path = os.path.join(os.environ["DNSMASQ_CONF_DIR"], "acme-validation.conf")

# Finally, write DNS record for dnsmasq to pick up
with open(path, "w") as stream:
    stream.write(f'txt-record={domain},"{validation}"')

# Sleep for two seconds:
# * The dnsmasq wrapper script will sleep for 1s before restarting dnsmasq
# * Add a second to be sure
time.sleep(2)
