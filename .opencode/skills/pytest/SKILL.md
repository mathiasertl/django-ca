---
name: pytest
description: Instructions for running, writing, and maintaining tests in this project
---

## Running tests

```bash
uv run pytest --no-selenium                       # all tests with coverage (slow)
uv run pytest --no-selenium --no-cov               # skip coverage (much faster for local work)
uv run pytest ca/django_ca/tests/test_models.py           # single file
uv run pytest ca/django_ca/tests/test_models.py::Cls::method  # single test
uv run pytest -k "test_something"    # keyword filter
```

## Critical test quirks

- `--cov-fail-under=100` is in `addopts` — 100% coverage is enforced by default. New code must be covered or use `# pragma: no cover` (version-conditional variants like `# pragma: only cryptography>46` also exist).
- Tests run in **random order** by default (`pytest-random-order`).
- `DJANGO_SETTINGS_MODULE=ca.test_settings` is set automatically by pytest-env.
- `ca/` and `docs/source/` are on `pythonpath` via pytest config — no need to set `PYTHONPATH` manually when running pytest.
- `cert-data.json` is loaded at `test_settings.py` import time; it must exist before any test run. Regenerate with `uv run python dev.py recreate-fixtures`.
- Selenium tests auto-skip unless on newest Python + cryptography + pydantic combo. Require Firefox + `contrib/selenium/geckodriver`.
- HSM tests require `softhsm2` (`apt-get install softhsm2`). Skip locally: `--no-hsm`.
- Crypto-related tests use pre-generated fixtures in `ca/django_ca/tests/`
- Do not regenerate fixtures unless explicitly asked.

## Test environment conventions

- **`COLUMNS=80`** is set in pytest env to make argparse output deterministic.
- **Pydantic models pre-imported** in `pytest_sessionstart` to avoid freezegun/Pydantic metaclass conflicts — do not move that import.
- **`CA_DIR = "/non/existent"`** in test settings — tests needing a real CA dir must use `override_settings` or a temp-dir fixture.


## Writing tests

- Tests are defined in `ca/django_ca/tests/`.
- Tests are grouped into submodules, e.g. `ca/django_ca/tests/models/test_<model>.py` for Django models.
- New tests are implemented as pytest-style functions, not `unittest.TestCase` classes.
- Class based unit tests are allowed for grouping, but pytest fixtures should be used instead of `setUp`/`tearDown`.

### Fixtures

This section provides generic instructions how to use fixtures.

- Always use pytest fixtures instead of `setUp`/`tearDown`-style functions.
- Globally available fixtures are defined in `ca/django_ca/tests/base/fixtures.py`.
- Fixtures required only by special cases (e.g. a special HTTP client used in many admin tests), define it in a
  `conftest.py` in the test submodule. If only a single `test_*.py file` needs it, define it in that file.
- A constant instead of a fixture can be used for trivial values, never change and are not stored in the database.
  Store them in `ca/django_ca/tests/base/constants.py` in this case.
- When using fixtures in the function definition, please use the following order:

  1. Standard pytest fixtures (e.g. `tmpdir`).
  2. Fixtures defined by plugins (e.g. `db`, `settings`, `client`).
  2. Fixtures defined in `conftest.py` (e.g. `db`, `settings`, `client`).

- If a fixture value only needs to be requested, use `request.getfixturevalue("fixture_name")` instead of adding it to
  the function signature to avoid linter warnings.
- The project defines a few dynamically created fixtures, they are documented in
  `/home/mertl/git/mati/django-ca/docs/source/dev/testing.rst`.