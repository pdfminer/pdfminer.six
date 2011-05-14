# GNUMakefile for test

RM=rm -f
CMP=:
PYTHON=python2

PDF2TXT=PYTHONPATH=.. $(PYTHON) ../tools/pdf2txt.py -p1 -V

HTMLS=$(HTMLS_FREE) $(HTMLS_NONFREE)
HTMLS_FREE= \
	simple1.html \
	simple2.html \
	simple3.html \
	jo.html
HTMLS_NONFREE= \
	nonfree/dmca.html \
	nonfree/f1040nr.html \
	nonfree/i1040nr.html \
	nonfree/kampo.html \
	nonfree/naacl06-shinyama.html \
	nonfree/nlp2004slides.html

TEXTS=$(TEXTS_FREE) $(TEXTS_NONFREE)
TEXTS_FREE= \
	simple1.txt \
	simple2.txt \
	simple3.txt \
	jo.txt
TEXTS_NONFREE= \
	nonfree/dmca.txt \
	nonfree/f1040nr.txt \
	nonfree/i1040nr.txt \
	nonfree/kampo.txt \
	nonfree/naacl06-shinyama.txt \
	nonfree/nlp2004slides.txt

XMLS=$(XMLS_FREE) $(XMLS_NONFREE)
XMLS_FREE= \
	simple1.xml \
	simple2.xml \
	simple3.xml \
	jo.xml
XMLS_NONFREE= \
	nonfree/dmca.xml \
	nonfree/f1040nr.xml \
	nonfree/i1040nr.xml \
	nonfree/kampo.xml \
	nonfree/naacl06-shinyama.xml \
	nonfree/nlp2004slides.xml

all: htmls texts xmls

test:
	$(MAKE) all CMP=cmp

clean:
	-$(RM) $(HTMLS)
	-$(RM) $(TEXTS)
	-$(RM) $(XMLS)

htmls: $(HTMLS)
texts: $(TEXTS)
xmls: $(XMLS)

.SUFFIXES: .pdf .html .xml .txt

.pdf.html:
	$(PDF2TXT) -t html -o $@ $<
	$(CMP) $@ $@.ref

.pdf.xml:
	$(PDF2TXT) -t xml -o $@ $<
	$(CMP) $@ $@.ref

.pdf.txt:
	$(PDF2TXT) -t text -o $@ $<
	$(CMP) $@ $@.ref
