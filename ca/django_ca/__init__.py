"""django-ca root module."""

import typing

# WARNING: This module MUST NOT include any dependencies, as it is read by setup.py

# https://www.python.org/dev/peps/pep-0440/
# https://www.python.org/dev/peps/pep-0396/
# https://www.python.org/dev/peps/pep-0386/
VERSION = (1, 22, 0)

# __version__ specified in PEP 0396, but we use the PEP 0440 format instead
__version__ = ".".join([str(e) for e in VERSION[:3]])
if len(VERSION) > 3:  # pragma: no cover
    # NOTE: dev_elements hack here only to make mypy happy in both dev and non-dev versions
    dev_elements: typing.Tuple[typing.Any, ...] = VERSION[3:5]
    __version__ += f".{''.join(str(e) for e in dev_elements)}"
