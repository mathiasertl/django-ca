# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = source
BUILDDIR      = build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile source/_files/docker-compose.yml source/_files/openapi.json extra-files

source/_files/docker-compose.yml:
	cp ../docker-compose.yml source/_files/

source/_files/openapi.json:
	DJANGO_SETTINGS_MODULE=ca.test_settings python ../ca/manage.py export_openapi_schema --api django_ca.api.endpoints.api > source/_files/openapi.json

extra-files: source/_files/openapi.json source/_files/docker-compose.yml

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile extra-files
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) -W -n $(O)
