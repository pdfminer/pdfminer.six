# Makefile for pdfminer

PACKAGE=pdfminer
VERSION=20090325
GNUTAR=tar
SVN=svn
PYTHON=python

WORKDIR=/tmp
DISTNAME=$(PACKAGE)-dist-$(VERSION)
DISTFILE=$(DISTNAME).tar.gz

CONV_CMAP=$(PYTHON) -m tools.conv_cmap

all:

cdbcmap: CMap
	-mkdir CDBCMap
	$(CONV_CMAP) CMap/*

test:
	cd samples && make

clean:
	cd pdflib && make clean
	cd tools && make clean
	cd samples && make clean

# Maintainance:

pack: clean
	$(SVN) cleanup
	$(SVN) export . $(WORKDIR)/$(DISTNAME)
	$(GNUTAR) c -z -C$(WORKDIR) -f $(WORKDIR)/$(DISTFILE) $(DISTNAME) --dereference --numeric-owner
	rm -rf $(WORKDIR)/$(DISTNAME)

check:
	-pychecker --limit=0 *.py

commit: clean
	$(SVN) commit

WEBDIR=$$HOME/Site/unixuser.org/python/pdfminer
publish: pack
	cp $(WORKDIR)/$(DISTFILE) $(WEBDIR)
	cp README.html $(WEBDIR)/index.html
