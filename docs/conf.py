# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'fowl'
copyright = '2023-2024, meejah'
author = 'meejah'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
html_theme_options = {
    'logo': 'logo.svg',
    'github_button': 'false',
    'github_user': 'meejah',
    'github_repo': 'fowl',
    'travis_button': 'false',
    'coveralls_button': 'false',
    'logo_name': 'true',
    'description': 'Forward any stream over peer-to-peer Wormhole connection',
    'logo_text_align': 'center',
    'note_bg': '#ccddcc',
    'note_border': '#839496',
}
