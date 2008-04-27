# Makefile for pdfminer

PACKAGE=pdfminer
VERSION=20080427
GNUTAR=tar
SVN=svn
PYTHON=python

WORKDIR=/tmp
DISTNAME=$(PACKAGE)-dist-$(VERSION)
DISTFILE=$(DISTNAME).tar.gz

all:

cdbcmap: CMap
	-mkdir CDBCMap
	$(PYTHON) conv_cmap.py CMap/*

clean:
	-rm *.pyc *.pyo *~

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
