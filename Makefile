# Makefile for pdfminer

PACKAGE=pdfminer
VERSION=20080629
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

samples:
	cd samples && make

clean:
	cd pdfminer && make clean
	cd tools && make clean
	cd samples && make clean

# Maintainance:

pack: clean
	$(SVN) cleanup
	$(SVN) export . $(WORKDIR)/$(DISTNAME)
	$(GNUTAR) c -z -C$(WORKDIR) -f $(WORKDIR)/$(DISTFILE) $(DISTNAME) --dereference --numeric-owner
	rm -rf $(WORKDIR)/$(DISTNAME)

pychecker:
	-pychecker --limit=0 *.py

commit: clean
	$(SVN) commit
