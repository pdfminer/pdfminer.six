# GNUMakefile for test

RM=rm -f
#CMP=cmp
CMP=:
PYTHON=python
PDF2TXT=PYTHONPATH=.. $(PYTHON) ../tools/pdf2txt.py -Dx -p1

HTMLS= \
	simple1.html \
	simple2.html \
	dmca.html \
	f1040nr.html \
	i1040nr.html \
	jo.html \
	kampo.html \
	naacl06-shinyama.html \
	nlp2004slides.html

TEXTS= \
	simple1.txt \
	simple2.txt \
	dmca.txt \
	f1040nr.txt \
	i1040nr.txt \
	jo.txt \
	kampo.txt \
	naacl06-shinyama.txt \
	nlp2004slides.txt

XMLS= \
	simple1.xml \
	simple2.xml \
	dmca.xml \
	f1040nr.xml \
	i1040nr.xml \
	jo.xml \
	kampo.xml \
	naacl06-shinyama.xml \
	nlp2004slides.xml

test: htmls texts xmls

clean:
	-$(RM) $(HTMLS)
	-$(RM) $(TEXTS)
	-$(RM) $(XMLS)

htmls: $(HTMLS)
texts: $(TEXTS)
xmls: $(XMLS)

.SUFFIXES: .pdf .html .xml .txt

.pdf.html:
	$(PDF2TXT) -t html $< > $@
	$(CMP) $@ $@.ref

.pdf.xml:
	$(PDF2TXT) -t xml $< > $@
	$(CMP) $@ $@.ref

.pdf.txt:
	$(PDF2TXT) -t text $< > $@
	$(CMP) $@ $@.ref
