# GNUMakefile for test

PYTHON=python
PDF2TXT=PYTHONPATH=.. $(PYTHON) -m tools.pdf2txt

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

.SUFFIXES: .pdf .html
.pdf.html:
	$(PDF2TXT) -H -o $@ $<
