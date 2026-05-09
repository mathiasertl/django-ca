# AGENTS.md — django-ca

## Overview

Single Django app (`ca/django_ca/`) for managing TLS certificate authorities. Not a monorepo. Python 3.11–3.14, Django 5.2/6.0, cryptography 46/47. Package manager: **`uv`** (required `>=0.11.3`).

## Context

This is a Python project providing a Public Key Infrastructure (PKI). It allows you to create and manage
CAs and end-entity certificates. It supports CRLs, OCSP, ACMEv2.

When you need to verify API behavior for Django, Celery, cryptography, pydantic, or acme,
use the `context7` tool to look up current docs before writing code.

## Relevant standards

* RFC 5280
* RFC 6960 - Online Certificate Status Protocol - OCSP
* RFC 7633 - TLS Feature Extension
* RFC 8555 - ACMEv2

## Critical Rules

- Cryptographic code MUST use the `cryptography` library primitives only.
  Never roll custom crypto.
- Certificate extensions follow RFC 5280 strictly. Reference the relevant RFC
  section in code comments when implementing extension logic.
- Pydantic models are used for config and serialization - use v2 API only.
- When touching CA or certificate issuance logic, always consider security
  implications and mention them explicitly.
- Operations requiring the use of private keys of CAs (e.g. signing, ...) should be implemented as Celery tasks.
- It is okay for Celery tasks to call key backends or functions in models to handle private keys.
- Management commands that require the use of private CA keys should only call the referenced Certificate
  Authority.

### Celery tasks

- Tasks that take parameters shall use the `DjangoCaTask` as base.
- Tasks take at most a single parameter, type-hinted to a Pydantic model. `DjangoCaTask` will convert
  parameters automatically.
- Tasks shall assert correctness of the typehint at run-time using an isinstance-assertion.

### Custom app settings

- Custom settings are settings used by this project that are not standard to Django or Celery.
- Custom settings must be reflected in `SettingsModel` located in `ca/django_ca/conf.py`.
- Custom settings must be documented in `docs/source/settings.rst`.
- Custom settings should have a useful default.
- Documentation uses a custom Sphinx extension to show valid values in different formats:
  - The `pydantic-setting` directive can be used to show a settings default value in different formats.
  - When documenting new settings, always show the default value using this directive first.
  - Additional example values MAY be added if examples show meaningful values first.
  - Add the `:example: N` option to show the N-th example from Pydantics field configuration.

## Coding Standards

* Python code should pass for ruff, mypy and pylint.

## Directory layout

```
ca/                        # Django project root (on sys.path as "ca")
  ca/                      # Django project package (settings, urls, wsgi, celery)
    test_settings.py       # used for ALL tests AND mypy
  django_ca/               # the installable app
    migrations/            # generated code, excluded from ruff, mypy, license checks
    tests/
      base/                # shared test infra (mixins, constants, conftest helpers)
      fixtures/            # checked-in binary cert/key files + cert-data.json
      conftest.py
devscripts/                # implementation of dev.py sub-commands
stubs/                     # hand-written type stubs for untyped third-party libs
docs/                      # Sphinx docs (separate from ca/docs/)
dev.py                     # central developer script — see sub-commands below
```

## Environment setup

```bash
uv sync --all-extras         # install all default groups (dev, dist, docs, lint, mypy, local)
```

## Running tests

```bash
uv run pytest --no-selenium                       # all tests with coverage (slow)
uv run pytest --no-selenium --no-cov               # skip coverage (much faster for local work)
uv run pytest ca/django_ca/tests/test_models.py           # single file
uv run pytest ca/django_ca/tests/test_models.py::Cls::method  # single test
uv run pytest -k "test_something"    # keyword filter
```

**Critical test quirks:**
- `--cov-fail-under=100` is in `addopts` — 100% coverage is enforced by default. New code must be covered or use `# pragma: no cover` (version-conditional variants like `# pragma: only cryptography>46` also exist).
- Tests run in **random order** by default (`pytest-random-order`).
- `DJANGO_SETTINGS_MODULE=ca.test_settings` is set automatically by pytest-env.
- `ca/` and `docs/source/` are on `pythonpath` via pytest config — no need to set `PYTHONPATH` manually when running pytest.
- `cert-data.json` is loaded at `test_settings.py` import time; it must exist before any test run. Regenerate with `uv run python dev.py recreate-fixtures`.
- Selenium tests auto-skip unless on newest Python + cryptography + pydantic combo. Require Firefox + `contrib/selenium/geckodriver`.
- HSM tests require `softhsm2` (`apt-get install softhsm2`). Skip locally: `--no-hsm`.
- Crypto-related tests use pre-generated fixtures in `ca/django_ca/tests/`
- Do not regenerate fixtures unless explicitly asked.

## Before running tests (first time or after fixture changes)

```bash
uv run python dev.py init-demo       # runs migrate + recreate-fixtures, seeds demo DB
```

For external DBs (Postgres/MariaDB), set `POSTGRES_HOST` or `MARIADB_HOST` env vars and run `manage.py migrate` first.

## Code quality (run before committing)

```bash
uv run python dev.py code-quality    # ruff format --diff, ruff check, pre-commit, manage.py check, makemigrations --check
uv run mypy .                        # strict mypy (uses ca/ca/test_settings.py + stubs/)
```

**Order matters in CI:** `code-quality` → `mypy` → `pytest`

Individual steps:
```bash
uv run ruff format .                 # apply formatting (line length 110)
uv run ruff check --fix .            # lint + auto-fix
uv run pylint ca/django_ca/ ca/ca/ docs/source/django_ca_sphinx/ devscripts/ dev.py  # slow, run separately
uv run python dev.py validate state  # checks version matrix consistency across CI/README/tox/pyproject.toml
uv run python dev.py validate license-headers  # GPL-3 header required on every non-migration .py file
```

## Migrations

Any model change requires a migration. `makemigrations --check` runs as part of `code-quality`. Generate:
```bash
DJANGO_SETTINGS_MODULE=ca.test_settings python ca/manage.py makemigrations
```
Migrations are excluded from ruff, mypy, and license header checks.

## Docs

```bash
uv run doc8 docs/source/             # RST style check (excludes docs/source/generated/)
uv run make -C docs html             # Sphinx build (warnings treated as errors via -W -n)
uv run make -C docs spelling
```

The `docs/Makefile` auto-generates `docs/source/_files/openapi.json` and `docs/source/_files/compose.yaml` before building. `docs/source/generated/` is auto-generated RST — do not edit manually.

## `dev.py` sub-commands

| Command | Purpose |
|---|---|
| `python dev.py init-demo` | Seed demo DB (runs migrate + recreate-fixtures) |
| `python dev.py code-quality` | ruff + pre-commit + Django checks |
| `python dev.py validate state` | Version/matrix consistency across all config files |
| `python dev.py validate license-headers` | GPL-3 header check |
| `python dev.py recreate-fixtures` | Regenerate test fixture files in `tests/fixtures/` |
| `python dev.py build ...` | Build artifacts |

## Conventions that differ from defaults

- **isort custom sections**: `future → stdlib → third-party → crypto → django → django-addon → test → first-party → local-folder`. Both `django_ca` and `ca` are `known-first-party`.
- **Max line length: 110** (ruff, pylint, doc8, editorconfig).
- **`stubs/`** on `mypy_path` — hand-written stubs for untyped libs (celery, webtest, pyvirtualdisplay, etc.). Do not delete.
- **`COLUMNS=80`** is set in pytest env to make argparse output deterministic.
- **Pydantic models pre-imported** in `pytest_sessionstart` to avoid freezegun/Pydantic metaclass conflicts — do not move that import.
- **`CA_DIR = "/non/existent"`** in test settings — tests needing a real CA dir must use `override_settings` or a temp-dir fixture.
- **`DJANGO_CA_SECRET_KEY`** env var must be set for `code-quality` and `docs` runs outside of tests (CI sets it to `"dummy"`).

## Tox

```bash
tox -e lint        # ruff + pre-commit + validate
tox -e pylint
tox -e mypy
tox -e docs
tox -e demo        # init-demo
tox -e faketime    # faketime -f +100y pytest --no-selenium
tox -e pkg         # uv build
```

Matrix: `py311-314 × dj5.2/6.0 × cg46/47 × acme5.4/5.5 × pydantic2.12/2.13`. Requires `tox-uv`.
