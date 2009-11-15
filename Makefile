##  Makefile (for maintainance purpose)
##

PACKAGE=pdfminer
PREFIX=/usr/local

SVN=svn
PYTHON=python
RM=rm -f
CP=cp -f

all:

install:
	$(PYTHON) setup.py install --prefix=$(PREFIX)

clean:
	-$(PYTHON) setup.py clean
	-$(RM) -r build dist
	-cd $(PACKAGE) && $(MAKE) clean
	-cd tools && $(MAKE) clean
	-cd samples && $(MAKE) clean

test:
	cd samples && $(MAKE) test

commit: clean
	$(SVN) commit

check:
	cd $(PACKAGE) && make check

register: clean
	$(PYTHON) setup.py sdist upload register

WEBDIR=$$HOME/Site/unixuser.org/python/$(PACKAGE)
publish:
	$(CP) docs/*.html $(WEBDIR)
