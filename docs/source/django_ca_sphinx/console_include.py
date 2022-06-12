# This file is part of django-ca (https://github.com/mathiasertl/django-ca).
#
# django-ca is free software: you can redistribute it and/or modify it under the terms of the GNU
# General Public License as published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# django-ca is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with django-ca. If not,
# see <http://www.gnu.org/licenses/>.

"""A directive that lets you include a Jinja2 template as a rendered code block."""

import re
import textwrap
import typing

from docutils.parsers.rst import directives
from jinja2 import Environment
from jinja2 import FileSystemLoader
from sphinx.directives.code import CodeBlock  # code-block directive from Sphinx
from sphinx.util.typing import OptionSpec
from yaml import load

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader  # type: ignore[misc]  # mypy complains about different type


class CommandLineTextWrapper(textwrap.TextWrapper):
    """Subclass of TextWrapper that "unsplits" a short option and its (supposed) value.

    This makes sure that a command with many options will not break between short options and their value,
    e.g. for ``docker run -e FOO=foo -e BAR=bar ...``, the text wrapper will never insert a line split between
    ``-e`` and its respective option value.

    Note that the class of course does not know the semantics of the command it renders. A short option
    followed by a value is always considered a reason not to break. For example, for ``docker run ... -d
    image``, the wrapper will never split between ``-d`` and ``image``, despite the latter being unrelated to
    the former.
    """

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        self.subsequent_indent = ">    "
        self.break_on_hyphens = False
        self.break_long_words = False

    def _unsplit_optargs(self, chunks: typing.List[str]) -> typing.Iterator[str]:
        unsplit: typing.List[str] = []
        for chunk in chunks:
            if re.match("-[a-z]$", chunk):  # chunk appears to be an option
                if unsplit:  # previous option was also an optarg, so yield what was there
                    for unsplit_chunk in unsplit:
                        yield unsplit_chunk
                unsplit = [chunk]
            elif chunk == " ":
                if unsplit:  # this is the whitespace after an option
                    unsplit.append(chunk)
                else:  # a whitespace not preceeded by an option
                    yield chunk
            else:  # not an option
                # The unsplit buffer has two values (short option and space) and this chunk looks like its
                # value, so yield the buffer and this value as split
                if len(unsplit) == 2 and re.match("[a-zA-Z0-9`]", chunk):
                    # unsplit option, whitespace and option value
                    unsplit.append(chunk)
                    yield "".join(unsplit)
                    unsplit = []

                # There is something in the unsplit buffer, but this chunk does not look like a value (maybe
                # it's a long option?), so we yield tokens from the buffer and then this chunk.
                elif unsplit:
                    for unsplit_chunk in unsplit:
                        yield unsplit_chunk
                    unsplit = []
                    yield chunk
                else:
                    yield chunk

        # yield any remaining chunks
        for chunk in unsplit:
            yield chunk

    def _split(self, text: str) -> typing.List[str]:
        chunks = super()._split(text)
        unsplit = list(self._unsplit_optargs(chunks))
        return unsplit


class ConsoleIncludeDirective(CodeBlock):
    """A directive to render shell commands from a YAML file with console syntax highlighing.

    django-ca uses this directive to have shell commands for tutorials in the documentation in a machine
    readable file which then can also be used by release test scripts.

    Usage::

        .. console-include::
        :include: commands.yaml
        :context: optional-context

    The above will use commands from :file:`commands.yaml` and use ``optional-context`` for each command and
    display it as code-block with console syntax highlighting. The directive takes care of propper line
    wrapping, with options and their values (e.g. ``-e some-value``) never used for line breaks.

    Options:

    include (reqired)
        Path to the YAML file, relative to the Sphinx document root.
    context
        Name of the ``jinja2_context`` to use for rendering commands.
    user (default: ``user``)
        User name to display in the prompt.
    host (default: ``host``)
        Host name to display in the prompt.
    path (default: ``~``)
        Current working directory to display in th prompt.
    root (default: ``False``)
        If set, display a ``#`` instead of a ``$`` to indicate that the user is a super user. This is the
        default if `user` is set to ``root``.
    line_length (default: ``75``)
        Line length to use, defaults to 75.

    The YAML file named in the include directive has a simple syntax, commands are rendered as Jinja2
    templates with the context named in ``context``:

    .. code-block:: yaml

       commands:
           - command: mkdir -p {{ path }}
           - command: rm -rf {{ path }}
    """

    required_arguments = 0
    has_content = False
    option_spec: OptionSpec = dict(
        CodeBlock.option_spec,
        include=directives.unchanged_required,
        context=directives.unchanged_required,
        user=directives.unchanged_required,
        host=directives.unchanged_required,
        path=directives.unchanged_required,
        root=directives.flag,
        line_length=directives.nonnegative_int,
    )

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.config.jinja_base, followlinks=True), **self.config.jinja_env_kwargs
        )
        self.jinja_env.filters.update(self.config.jinja_filters)
        self.jinja_env.tests.update(self.config.jinja_tests)
        self.jinja_env.globals.update(self.config.jinja_globals)
        # TYPEHINT NOTE: false positive
        self.jinja_env.policies.update(self.config.jinja_policies)  # type: ignore[attr-defined]

    @property
    def arguments(self) -> typing.List[str]:
        """Return static argument "console"."""
        return ["console"]

    @arguments.setter
    def arguments(self, value: typing.Any) -> None:
        pass

    def _split_command(self, prompt: str, command: str) -> typing.List[str]:
        """Smartly split command into multiple lines."""
        line_length = self.options.get("line_length", 75)
        command = re.sub(r"\s+", " ", command)

        wrapper = CommandLineTextWrapper(width=line_length)
        lines = wrapper.wrap(f"{prompt} {command}")

        lines = [f"{line} \\" if i != len(lines) else line for i, line in enumerate(lines, 1)]
        return lines

    @property
    def content(self) -> typing.List[str]:
        """Actually render the template."""

        include = self.options.get("include")
        if not include:
            raise ValueError("No include specified.")

        rel_filename, filename = self.env.relfn2path(include)
        with open(filename, encoding="utf-8") as stream:
            commands = load(stream, Loader=Loader)["commands"]

        context_name = self.options.get("context")
        if not context_name:
            context = {}
        elif context_name not in self.config.jinja_contexts:
            raise ValueError(f"{context_name}: Unknow context specified.")
        else:
            context = self.config.jinja_contexts[context_name].copy()

        root = "root" in self.options
        if root:
            default_user = "root"
        else:
            default_user = "user"

        user = self.options.get("user", default_user)
        host = self.options.get("host", "host")
        path = self.options.get("path", "~")

        lines = []
        for config in commands:
            if root:
                delimiter = "#"
            else:
                delimiter = "$"
            prompt = f"{user}@{host}:{path}{delimiter}"

            command = config["command"]
            template = self.jinja_env.from_string(config["command"])
            command = template.render(context)

            lines += self._split_command(prompt, command)

        return lines

    @content.setter
    def content(self, value: typing.Any) -> None:
        """Setter for content (used by the constructor). Disregards the value."""
