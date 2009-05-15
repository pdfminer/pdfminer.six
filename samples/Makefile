# GNUMakefile for test

PYTHON=python
CMAPDIR=../CMap
CDBCMAPDIR=../CDBCMap
PDF2TXT=PYTHONPATH=.. $(PYTHON) ../tools/pdf2txt.py -C$(CMAPDIR) -D$(CDBCMAPDIR)

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

all: $(HTMLS)

clean:
	-rm $(HTMLS)

.SUFFIXES: .pdf .html .sgml .txt
.pdf.html:
	$(PDF2TXT) -t html -o $@ $<
.pdf.sgml:
	$(PDF2TXT) -t sgml -o $@ $<
.pdf.txt:
	$(PDF2TXT) -t text -o $@ $<
