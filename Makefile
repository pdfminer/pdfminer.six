##  Makefile (for maintenance purpose)
##

PACKAGE=pdfminer

PYTHON=python
GIT=git
RM=rm -f
CP=cp -f
MKDIR=mkdir

all:

install:
	$(PYTHON) setup.py install --home=$(HOME)

clean:
	-$(PYTHON) setup.py clean
	-$(RM) -r build dist MANIFEST
	-cd $(PACKAGE) && $(MAKE) clean
	-cd tools && $(MAKE) clean
	-cd samples && $(MAKE) clean

distclean: clean cmap_clean

sdist: distclean MANIFEST.in
	$(PYTHON) setup.py sdist
register: distclean MANIFEST.in
	$(PYTHON) setup.py sdist upload register

WEBDIR=../euske.github.io/$(PACKAGE)
publish:
	$(CP) docs/*.html docs/*.png docs/*.css $(WEBDIR)

CMAPDST=pdfminer/cmap
cmap_clean:
	-$(RM) -r $(CMAPDST)

test: cmap
	nosetests
	cd samples && $(MAKE) test
