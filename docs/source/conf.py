# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

import os, sys
sys.path.insert(0, os.path.abspath('../..'))

project = 'Security Labs'
copyright = '2026, Logan Jacobs'
author = 'Logan Jacobs'
release = '0.1'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
    "sphinx.ext.githubpages",
]

# Napoleon settings (for docstring parsing)
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = True
napoleon_include_special_with_doc = True  # THIS IS CRITICAL - includes __contains__, __getitem__
napoleon_use_ivar = True

# Autodoc settings - these control what gets documented
autodoc_default_options = {
    'members': True,           # Include class members
    'member-order': 'bysource', # Order as in source code
    'special-members': '__init__, __contains__, __getitem__, __str__',
    'undoc-members': True,     # Include members without docstrings
    'exclude-members': '__weakref__',  # Exclude this internal member
    'show-inheritance': True,  # Show class inheritance
}
autodoc_typehints = 'description'

templates_path = ['_templates']
# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
html_show_sphinx = False
html_show_copyright = True
# If using Read the Docs theme
html_theme_options = {
    'collapse_navigation': False,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False
}
