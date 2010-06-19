##  Makefile (for maintainance purpose)
##

PACKAGE=pdfminer
PREFIX=/usr/local

PYTHON=python
RM=rm -f
CP=cp -f

all:

install:
	$(PYTHON) setup.py install --prefix=$(PREFIX)

clean:
	-$(PYTHON) setup.py clean
	-$(RM) -r build dist MANIFEST
	-cd $(PACKAGE) && $(MAKE) clean
	-cd tools && $(MAKE) clean

distclean: clean test_clean cmap_clean

pack: distclean MANIFEST
	$(PYTHON) setup.py sdist
register: distclean
	$(PYTHON) setup.py sdist upload register

WEBDIR=$$HOME/Site/unixuser.org/python/$(PACKAGE)
publish:
	$(CP) docs/*.html $(WEBDIR)

CONV_CMAP=$(PYTHON) tools/conv_cmap.py
CMAPSRC=cmaprsrc
CMAPDST=pdfminer/cmap
cmap: $(CMAPDST)/to-unicode-Adobe-CNS1.pickle.gz $(CMAPDST)/to-unicode-Adobe-GB1.pickle.gz \
	$(CMAPDST)/to-unicode-Adobe-Japan1.pickle.gz $(CMAPDST)/to-unicode-Adobe-Korea1.pickle.gz
cmap_clean:
	cd $(CMAPDST) && make cmap_clean
$(CMAPDST)/to-unicode-Adobe-CNS1.pickle.gz:
	$(CONV_CMAP) $(CMAPDST) Adobe-CNS1 $(CMAPSRC)/cid2code_Adobe_CNS1.txt cp950 big5
$(CMAPDST)/to-unicode-Adobe-GB1.pickle.gz:
	$(CONV_CMAP) $(CMAPDST) Adobe-GB1 $(CMAPSRC)/cid2code_Adobe_GB1.txt cp936 gb2312
$(CMAPDST)/to-unicode-Adobe-Japan1.pickle.gz:
	$(CONV_CMAP) $(CMAPDST) Adobe-Japan1 $(CMAPSRC)/cid2code_Adobe_Japan1.txt cp932 euc-jp
$(CMAPDST)/to-unicode-Adobe-Korea1.pickle.gz:
	$(CONV_CMAP) $(CMAPDST) Adobe-Korea1 $(CMAPSRC)/cid2code_Adobe_Korea1.txt cp949 euc-kr

test: cmap
	cd samples && $(MAKE) test CMP=cmp
test_clean:
	-cd samples && $(MAKE) clean

SED=sed
FIND=find . '(' -name .git -o -name .svn -o -name CVS -o -name dev -o -name dist -o -name build ')' -prune -false -o
SORT=sort
TOUCH=touch
MANIFEST:
	$(TOUCH) MANIFEST
	$(FIND) -type f '!' -name '.*' | $(SED) 's:./::' | $(SORT) > MANIFEST
