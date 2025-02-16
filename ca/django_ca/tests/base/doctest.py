# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU General
# Public License as published by the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not, see
# <http://www.gnu.org/licenses/>.

"""Helper functions for doctests."""

import doctest
import importlib
import re

STRIP_WHITESPACE = doctest.register_optionflag("STRIP_WHITESPACE")


class OutputChecker(doctest.OutputChecker):
    """Custom output checker to enable the STRIP_WHITESPACE option."""

    def check_output(self, want: str, got: str, optionflags: int) -> bool:
        if optionflags & STRIP_WHITESPACE:
            want = re.sub(r"\s*", "", want)
            got = re.sub(r"\s*", "", got)
        return super().check_output(want, got, optionflags)


def doctest_module(
    module: str,
    name: str | None = None,
    globs: dict[str, str] | None = None,
    verbose: bool | None = False,
    report: bool = False,
    optionflags: int = 0,
    extraglobs: dict[str, str] | None = None,
    raise_on_error: bool = False,
    exclude_empty: bool = False,
) -> doctest.TestResults:
    """Shortcut for running doctests in the given Python module.

    This function is based on :py:func:`doctest.testmod`. It differs in that it will add the
    ``STRIP_WHITESPACE`` doctest option and interpret `module` as module path if a ``str`` and import the
    module. The `report` and `verbose` flags also default to ``False``, as this provides cleaner output in
    modules with a lot of doctests.
    """
    finder = doctest.DocTestFinder(exclude_empty=exclude_empty)
    checker = OutputChecker()

    if raise_on_error:  # pragma: no cover  # only used for debugging
        runner: doctest.DocTestRunner = doctest.DebugRunner(
            verbose=verbose, optionflags=optionflags, checker=checker
        )
    else:
        runner = doctest.DocTestRunner(verbose=verbose, optionflags=optionflags, checker=checker)

    mod = importlib.import_module(module)

    for test in finder.find(mod, name, globs=globs, extraglobs=extraglobs):
        runner.run(test)

    if report:  # pragma: no cover  # only used for debugging
        runner.summarize()

    return doctest.TestResults(runner.failures, runner.tries)
