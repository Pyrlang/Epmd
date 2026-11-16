"""Sphinx configuration of the Epmd documentation.

Build (the same command on Windows, in WSL and in CI), with the package
installed and the ``docs`` dependency group::

    python -m sphinx -W --keep-going -b html docs-src/source docs-src/build/html
"""

import os
from datetime import date
from importlib import metadata

# Where the Pyrlang sites are published, one directory per project
# (``/pyrlang/``, ``/term/``, ``/epmd/``). ``PYRLANG_DOCS_BASE_URL`` overrides
# it for a staging host.
DOCS_BASE_URL: str = os.environ.get(
    "PYRLANG_DOCS_BASE_URL", "https://pyrlang.clau.se"
).rstrip("/")

project = "Epmd"
author = "Amit Garu, Dmytro Lytovchenko, Johan Sommerfeld"
copyright = "2019-%d, Erlang Solutions Ltd., S2HC Sweden AB" % date.today().year
release = metadata.version("epmd")
version = release
language = "en"

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
]
templates_path = ["_templates"]
exclude_patterns: list[str] = []

# Every unresolved cross-reference is a warning, and the build runs with -W.
nitpicky = True
# The base class of EpmdProtocol, under the name its module gives it; the
# Python documentation has it as asyncio.Protocol.
nitpick_ignore = [("py:class", "asyncio.protocols.Protocol")]

autosummary_generate = True
# Read by _templates/autosummary/module.rst: modules left out of the
# reference. ``python -m epmd`` is described on the index page.
autosummary_context = {"skip_modules": ["epmd.__main__"]}
autodoc_member_order = "bysource"
autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"

myst_heading_anchors = 3

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

html_theme = "furo"
html_title = "Epmd %s" % release
html_baseurl = DOCS_BASE_URL + "/epmd/"
# Links to the sibling sites, for use in the pages as {{ term_site }}.
# Whole links: MyST substitutes text, not the URL inside [text](url).
myst_substitutions = {
    "pyrlang_site": "[Pyrlang](%s/pyrlang/)" % DOCS_BASE_URL,
    "term_site": "[Term](%s/term/)" % DOCS_BASE_URL,
}
myst_enable_extensions = ["substitution"]
