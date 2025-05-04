"""Gunicorn configuration file.

Gunicorn is responsible for serving HTTP requests.

For a list of available settings, please see the official documentation:

    https://docs.gunicorn.org/en/latest/settings.html
"""

import multiprocessing

# Use the given number of worker processes to handle request:
workers = multiprocessing.cpu_count() * 2 + 1

# Bind to a local Unix socket to improve performance. If your webserver
# runs on a different host, you need to use a TCP socket.
# bind = "127.0.0.1:8000"
