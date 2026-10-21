# Sphinx configuration for the fakenet-hybrid documentation (Read the Docs style).
# Build: pip install -r docs/requirements.txt && sphinx-build -b html docs docs/_build/html

project = "FakeNet hybrid"
author = "fakenet-hybrid contributors"
copyright = "2026, fakenet-hybrid contributors"
release = "0.1.0"

extensions = ["myst_parser", "sphinx.ext.autosectionlabel"]
myst_enable_extensions = ["colon_fence", "deflist", "tasklist"]
myst_heading_anchors = 3
autosectionlabel_prefix_document = True
suppress_warnings = ["autosectionlabel.*"]

source_suffix = {".md": "markdown"}
root_doc = "index"
exclude_patterns = ["_build", "ARCHITECTURE.md"]

html_theme = "sphinx_rtd_theme"
html_title = "FakeNet hybrid documentation"
html_static_path = ["_static"]
html_theme_options = {"navigation_depth": 3, "collapse_navigation": False}
