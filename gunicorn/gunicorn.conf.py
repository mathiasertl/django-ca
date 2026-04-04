"""Gunicorn configuration file.

Gunicorn is responsible for serving HTTP requests.

For a list of available settings, please see the official documentation:

    https://gunicorn.org/reference/settings/
"""

import multiprocessing

# Use the given number of worker processes to handle request:
workers = multiprocessing.cpu_count() * 2 + 1

# Bind to a local Unix socket to improve performance. If your webserver
# (e.g. NGINX) runs on a different host, you need to use a TCP socket.
# bind = "127.0.0.1:8000"

# Disable Control Interface: https://gunicorn.org/guides/gunicornc/
control_socket_disable = True

# To enable the control socket in SystemD services, you'll have to make sure
# the path for the socket is writable, as `ProtectSystem=strict` is set.
# The safest way is to set a RuntimeDirectory. In the service:
#
#   RuntimeDirectory=%N
#   RuntimeDirectoryMode=0750
#
# And uncomment the lines below (adn add an `import os` at the top):
# if runtime_directory := os.environ.get("RUNTIME_DIRECTORY"):
#    control_socket = f"{runtime_directory}/gunicorn.ctl"
#    control_socket_mode = 0o660  # Allow group access
