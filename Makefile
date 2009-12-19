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

CONV_CMAP=$(PYTHON) tools/conv_cmap.py
CMAPDIR=pdfminer/cmap
CMAPRSRC=cmaprsrc
cmap: cmaprsrc
	$(CONV_CMAP) $(CMAPDIR) Adobe-CNS1 $(CMAPRSRC)/cid2code_Adobe_CNS1.txt cp950 big5
	$(CONV_CMAP) $(CMAPDIR) Adobe-GB1 $(CMAPRSRC)/cid2code_Adobe_GB1.txt cp936 gb2312
	$(CONV_CMAP) $(CMAPDIR) Adobe-Japan1 $(CMAPRSRC)/cid2code_Adobe_Japan1.txt cp932 euc-jp
	$(CONV_CMAP) $(CMAPDIR) Adobe-Korea1 $(CMAPRSRC)/cid2code_Adobe_Korea1.txt cp949 euc-kr

cmap_clean:
	cd $(CMAPDIR) && make cmap_clean
