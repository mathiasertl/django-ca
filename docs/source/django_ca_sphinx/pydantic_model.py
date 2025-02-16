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

"""Sphinx extension providing the ``pydantic-model`` directive."""

import ast
import difflib
import textwrap
from typing import Any, ClassVar

import yaml
from docutils.nodes import paragraph
from docutils.parsers.rst import directives
from docutils.parsers.rst.states import Body
from docutils.statemachine import StringList
from sphinx.util.docutils import SphinxDirective
from sphinx.util.typing import OptionSpec

from cryptography import x509

from django_ca.profiles import Profile
from django_ca.pydantic.base import CryptographyModel
from django_ca.pydantic.extensions import ExtensionModel

TAB_INDENT = " " * 6


class PydanticModelDirectiveBase(SphinxDirective):
    """Base class providing common functionalities for both directives."""

    def exec_with_return(self, code: str) -> Any:
        """Function to execute a multi-line code block and return the value of the last statement.

        .. seealso:: https://stackoverflow.com/a/76636602
        """
        global_variables: dict[str, Any] = {}

        a = ast.parse(code)
        last_expression = None
        if a.body:
            if isinstance(a_last := a.body[-1], ast.Expr):
                last_expression = ast.unparse(a.body.pop())
            elif isinstance(a_last, ast.Assign):
                last_expression = ast.unparse(a_last.targets[0])
            elif isinstance(a_last, ast.AnnAssign | ast.AugAssign):
                last_expression = ast.unparse(a_last.target)
        exec(ast.unparse(a), global_variables)  # pylint: disable=exec-used
        if last_expression:
            return eval(last_expression, global_variables)  # pylint: disable=eval-used

    def get_code(self, prefix: str, suffix: str) -> tuple[str, str]:
        """Load Python code from a file in `/include/pydantic/{prefix}_{suffix}`."""
        # Get path to included Python file
        rel_filename, filename = self.env.relfn2path(f"/include/pydantic/{prefix}_{suffix}.py")
        self.env.note_dependency(rel_filename)

        try:
            with open(filename, encoding="utf-8", errors="strict") as stream:
                return filename, stream.read()
        except FileNotFoundError as ex:
            raise ValueError(f"{rel_filename}: File not found.") from ex

    def diff(self, a: Any, b: Any, from_file: str, to_file: str, what: str) -> str:
        """Generate diff for better readable output."""
        from_lines = repr(a).splitlines()
        to_lines = repr(b).splitlines()
        diff = difflib.unified_diff(from_lines, to_lines, from_file, to_file, lineterm="")
        diff_text = "\n".join(diff)
        return f"{what} differs:\n{diff_text}"

    def get_text(self) -> str:
        """Get text for this directive - needs to be implemented."""
        raise NotImplementedError

    def run(self) -> list[paragraph]:
        node = paragraph()
        text = self.get_text()
        lines = StringList(text.splitlines())
        state: Body = self.state
        state.nested_parse(lines, 0, node)
        return [node]


class PydanticModelDirective(PydanticModelDirectiveBase):
    """The ``pydantic-model`` directive."""

    required_arguments = 1
    option_spec: ClassVar[OptionSpec] = {
        "model-prefix": directives.unchanged_required,
        "cryptography-prefix": directives.unchanged_required,
    }

    def get_text(self) -> str:
        model_prefix = self.options.get("model-prefix", self.arguments[0])
        cryptography_prefix = self.options.get("cryptography-prefix", self.arguments[0])

        model_filename, model_code = self.get_code(model_prefix, "model")
        cryptography_filename, cryptography_code = self.get_code(cryptography_prefix, "cryptography")

        # Get value of the last line in the included cryptography file
        try:
            extension: x509.Extension[x509.ExtensionType] = self.exec_with_return(cryptography_code)
        except Exception as ex:
            raise RuntimeError(f"{cryptography_filename}: Cannot execute code: {ex}") from ex

        # Get value of the last line in the included Model file
        try:
            model: CryptographyModel[Any] = self.exec_with_return(model_code)
        except Exception as ex:
            raise RuntimeError(f"{model_filename}: Cannot execute code: {ex}") from ex

        try:
            converted_extension = model.cryptography
        except Exception as ex:
            raise RuntimeError(f"{model_filename}: Cannot convert to cryptography: {ex}") from ex

        try:
            converted_model = model.__class__.model_validate(extension)
        except Exception as ex:
            raise RuntimeError(f"{cryptography_filename}: Cannot call model_validate: {ex}") from ex

        # Verify that the two values are equivalent
        assert extension == converted_extension, self.diff(
            extension, converted_extension, cryptography_filename, model_filename, "Converted extension"
        )
        assert model == converted_model, self.diff(
            model, converted_model, model_filename, cryptography_filename, "Loaded model"
        )

        return f"""
.. tab:: Pydantic
   
   .. code-block:: python

{textwrap.indent(model_code, TAB_INDENT)}
   
.. tab:: cryptography

   .. code-block:: python
      
{textwrap.indent(cryptography_code, TAB_INDENT)}

.. tab:: JSON

   .. code-block:: JSON
   
{textwrap.indent(model.model_dump_json(indent=4), TAB_INDENT)}
"""


class PydanticProfileExtensionDirective(PydanticModelDirectiveBase):
    """The ``pydantic-profile-extension`` directive."""

    required_arguments = 1
    option_spec: ClassVar[OptionSpec] = {
        "yaml-text": directives.unchanged_required,
    }

    def get_text(self) -> str:
        profile_name = "example-profile"
        yaml_text = self.options.get("yaml-text", "")
        model_filename, model_code = self.get_code(self.arguments[0], "model")
        profile_filename, profile_code = self.get_code(self.arguments[0], "profile")

        # Get value of the last line in the included Model file
        try:
            model: ExtensionModel[Any] = self.exec_with_return(model_code)
        except Exception as ex:
            raise RuntimeError(f"{model_filename}: Cannot execute code: {ex}") from ex

        # Get value of the last line in the included profile file
        try:
            global_vars: dict[str, Any] = {}
            exec(profile_code, global_vars)  # pylint: disable=exec-used
            profile_data_from_python = global_vars["CA_PROFILES"][profile_name]
        except Exception as ex:
            raise RuntimeError(f"{profile_filename}: Cannot execute code: {ex}") from ex

        data = model.model_dump(mode="json", exclude_unset=True)
        profile_data_from_model = {"extensions": {model.type: data}}
        ca_profiles_from_model = {"CA_PROFILES": {profile_name: profile_data_from_model}}

        profile_from_model = Profile(profile_name, **profile_data_from_model)  # type: ignore[arg-type]
        profile_from_python = Profile(profile_name, **profile_data_from_python)
        assert profile_from_model == profile_from_python, self.diff(
            profile_data_from_model, profile_data_from_python, model_filename, profile_filename, "Profiles"
        )

        return f"""
.. tab:: Python
    
   .. code-block:: python
   
{textwrap.indent(profile_code, TAB_INDENT)}

.. tab:: YAML

   {yaml_text}

   .. code-block:: YAML

{textwrap.indent(yaml.dump(ca_profiles_from_model, indent=2), TAB_INDENT)}
"""
