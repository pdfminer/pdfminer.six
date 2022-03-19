##  Makefile (for maintenance purpose)
##

PYTHON=python
RM=rm -f
CP=cp -f
MKDIR=mkdir

CONV_CMAP=$(PYTHON) tools/conv_cmap.py
CMAPSRC=cmaprsrc
CMAPDST=pdfminer/cmap
cmap: $(CMAPDST)/to-unicode-Adobe-CNS1.pickle.gz $(CMAPDST)/to-unicode-Adobe-GB1.pickle.gz \
	$(CMAPDST)/to-unicode-Adobe-Japan1.pickle.gz $(CMAPDST)/to-unicode-Adobe-Korea1.pickle.gz
cmap_clean:
	-$(RM) -r $(CMAPDST)
$(CMAPDST):
	$(MKDIR) $(CMAPDST)
$(CMAPDST)/to-unicode-Adobe-CNS1.pickle.gz: $(CMAPDST)
	$(CONV_CMAP) -c B5=cp950 -c UniCNS-UTF8=utf-8 \
		$(CMAPDST) Adobe-CNS1 $(CMAPSRC)/cid2code_Adobe_CNS1.txt
$(CMAPDST)/to-unicode-Adobe-GB1.pickle.gz: $(CMAPDST)
	$(CONV_CMAP) -c GBK-EUC=cp936 -c UniGB-UTF8=utf-8 \
		$(CMAPDST) Adobe-GB1 $(CMAPSRC)/cid2code_Adobe_GB1.txt
$(CMAPDST)/to-unicode-Adobe-Japan1.pickle.gz: $(CMAPDST)
	$(CONV_CMAP) -c RKSJ=cp932 -c EUC=euc-jp -c UniJIS-UTF8=utf-8 \
		$(CMAPDST) Adobe-Japan1 $(CMAPSRC)/cid2code_Adobe_Japan1.txt
$(CMAPDST)/to-unicode-Adobe-Korea1.pickle.gz: $(CMAPDST)
	$(CONV_CMAP) -c KSC-EUC=euc-kr -c KSC-Johab=johab -c KSCms-UHC=cp949 -c UniKS-UTF8=utf-8 \
		$(CMAPDST) Adobe-Korea1 $(CMAPSRC)/cid2code_Adobe_Korea1.txt
