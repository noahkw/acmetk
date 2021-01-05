# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

sys.path.insert(0, os.path.abspath(".."))

# -- Variables ---------------------------------------------------------------

rst_prolog = """
.. |GIT_URL| replace:: https://gitlab.uni-hannover.de/ma-woehler/acme-broker.git
"""

# -- Project information -----------------------------------------------------

project = "ACME Toolkit"
copyright = "2020, Noah Wöhler"
author = "Noah Wöhler"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx-prompt",
    "sphinx_substitution_extensions",
]

intersphinx_mapping = {
    "aiohttp": ("https://docs.aiohttp.org/en/latest/", None),
    "acme": ("https://acme-python.readthedocs.io/en/latest/", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
    "dns": ("https://dnspython.readthedocs.io/en/latest/", None),
    "josepy": ("https://python-jose.readthedocs.io/en/latest/", None),
    "python": ("https://docs.python.org/3", None),
}

autodoc_default_options = {"private-members": True}

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
import sphinx_glpi_theme

html_theme = "glpi"
html_theme_path = sphinx_glpi_theme.get_html_themes_path()

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]
