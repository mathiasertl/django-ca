---
name: liveserver
description: Start a local Django development server and make HTTP requests against it for interactive endpoint testing
---

## Overview

The live server uses `liveserver_settings.py` (located alongside this file in `.opencode/skills/liveserver/`)
and runs on `http://127.0.0.1:8001`. All commands below must be run from the **repo root**.

The settings file is loaded by adding its directory to `PYTHONPATH` at invocation time:

```bash
PYTHONPATH=.opencode/skills/liveserver DJANGO_SETTINGS_MODULE=liveserver_settings
```
It provides a persistent SQLite database and real CA file storage — independent of the test suite.

`CA_USE_CELERY = False` so all tasks (CRL generation, OCSP key creation, etc.) run synchronously in-process —
no Celery worker is needed.

## Initial setup (first time only, or after deleting the database)

```bash
# Create the CA files directory
mkdir -p ca/liveserver_files

# Apply migrations to create the local SQLite database
PYTHONPATH=.opencode/skills/liveserver DJANGO_SETTINGS_MODULE=liveserver_settings \
    uv run python ca/manage.py migrate

# Create a superuser for admin access
PYTHONPATH=.opencode/skills/liveserver DJANGO_SETTINGS_MODULE=liveserver_settings \
    uv run python ca/manage.py createsuperuser
```

## Starting the server

First, check whether it is already running:

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8001/django_ca/ 2>/dev/null
```

If that returns `301` or `200`, the server is already up — skip starting it.

Otherwise, start it in the background:

```bash
PYTHONPATH=.opencode/skills/liveserver DJANGO_SETTINGS_MODULE=liveserver_settings \
    uv run python ca/manage.py runserver 127.0.0.1:8001 \
    > .opencode/skills/liveserver/liveserver.log 2>&1 &
echo $! > .opencode/skills/liveserver/liveserver.pid
sleep 2  # wait for startup
```

Verify it started successfully:

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8001/django_ca/
```

Check logs if something looks wrong:

```bash
cat .opencode/skills/liveserver/liveserver.log
```

## Making HTTP requests

Use the **FetchMCP** tool for all requests. The base URL is `http://127.0.0.1:8001`.

### Key URLs

| Endpoint | URL |
|---|---|
| Admin interface | `http://127.0.0.1:8001/admin/` |
| REST API root | `http://127.0.0.1:8001/django_ca/api/` |
| ACME directory | `http://127.0.0.1:8001/django_ca/acme/directory/` |
| CRL (per CA) | `http://127.0.0.1:8001/django_ca/crl/<serial>/` |
| OCSP (per CA) | `http://127.0.0.1:8001/django_ca/ocsp/<serial>/` |

### Authentication

- **Admin / session-based views**: POST to `/admin/login/` with `username`, `password`, and `csrfmiddlewaretoken`. Retrieve the CSRF token first with a GET to the login page (look for `csrfmiddlewaretoken` in the HTML or `csrftoken` cookie).
- **REST API**: The API uses session auth by default. Log in via admin first and reuse the session cookie, or check `CA_ENABLE_REST_API` endpoints for token auth options.
- **OCSP / CRL**: No authentication needed — these are public endpoints.

### CSRF for POST requests

1. GET the target page (e.g. `/admin/login/`) and extract the `csrftoken` cookie value.
2. Include it as both the `X-CSRFToken` header and the `csrfmiddlewaretoken` form field on all POST/PUT/DELETE requests.

## Stopping the server

```bash
kill "$(cat .opencode/skills/liveserver/liveserver.pid)" 2>/dev/null \
    || pkill -f "manage.py runserver 127.0.0.1:8001"
rm -f .opencode/skills/liveserver/liveserver.pid
```

## Resetting state

To start fresh (wipe DB and CA files):

```bash
rm -f ca/liveserver.sqlite3
rm -rf ca/liveserver_files/
mkdir -p ca/liveserver_files
PYTHONPATH=.opencode/skills/liveserver DJANGO_SETTINGS_MODULE=liveserver_settings \
    uv run python ca/manage.py migrate
PYTHONPATH=.opencode/skills/liveserver DJANGO_SETTINGS_MODULE=liveserver_settings \
    uv run python ca/manage.py createsuperuser
```
