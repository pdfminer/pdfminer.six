# GNUMakefile for test

RM=rm -f
CMP=:
ECHO=echo
PYTHON=python2
PYTHON3=python3

PDF2TXT=PYTHONPATH=.. $(PYTHON) ../tools/pdf2txt.py -p1 -V
PDF2TXT3=PYTHONPATH=.. $(PYTHON3) ../tools/pdf2txt.py -p1 -V

FREE= \
	simple1 \
	simple2 \
	simple3 \
	jo

NONFREE= \
	nonfree/dmca \
	nonfree/f1040nr \
	nonfree/i1040nr \
	nonfree/kampo \
	nonfree/naacl06-shinyama \
	nonfree/nlp2004slides

TESTS=$(FREE) $(NONFREE)

CRYPT_PASS1=foo
CRYPT_PASS2=baz
CRYPT_BASE=encryption/base
CRYPTS= \
	encryption/rc4-40 \
	encryption/rc4-128 \
	encryption/aes-128 \
	encryption/aes-128-m \
	encryption/aes-256 \
	encryption/aes-256-m

all: tests crypts

tests:
	for i in $(TESTS); do \
		$(ECHO) $$i; \
		$(PDF2TXT) -t html -o $$i.html $$i.pdf || exit 1; \
		$(CMP) $$i.html $$i.html.ref || exit 1; \
		$(PDF2TXT) -t xml -o $$i.xml $$i.pdf || exit 1; \
		$(CMP) $$i.xml $$i.xml.ref || exit 1; \
		$(PDF2TXT) -t text -o $$i.txt $$i.pdf || exit 1; \
		$(CMP) $$i.txt $$i.txt.ref || exit 1; \
		$(PDF2TXT3) -t html -o $$i.html $$i.pdf || exit 1; \
		$(CMP) $$i.html $$i.html.ref || exit 1; \
		$(PDF2TXT3) -t xml -o $$i.xml $$i.pdf || exit 1; \
		$(CMP) $$i.xml $$i.xml.ref || exit 1; \
		$(PDF2TXT3) -t text -o $$i.txt $$i.pdf || exit 1; \
		$(CMP) $$i.txt $$i.txt.ref || exit 1; \
	done

crypts:
	for i in $(CRYPTS); do \
		$(ECHO) $$i; \
		$(PDF2TXT) -t xml -P $(CRYPT_PASS1) -o $$i.1.xml $$i.pdf || exit 1; \
		$(CMP) $$i.1.xml $(CRYPT_BASE).xml || exit 1; \
		$(PDF2TXT) -t xml -P $(CRYPT_PASS2) -o $$i.2.xml $$i.pdf || exit 1; \
		$(CMP) $$i.2.xml $(CRYPT_BASE).xml || exit 1; \
		$(PDF2TXT3) -t xml -P $(CRYPT_PASS1) -o $$i.1.xml $$i.pdf || exit 1; \
		$(CMP) $$i.1.xml $(CRYPT_BASE).xml || exit 1; \
		$(PDF2TXT3) -t xml -P $(CRYPT_PASS2) -o $$i.2.xml $$i.pdf || exit 1; \
		$(CMP) $$i.2.xml $(CRYPT_BASE).xml || exit 1; \
	done

test:
	$(MAKE) all CMP=cmp

clean:
	-for i in $(TESTS); do \
		$(RM) $$i.html $$i.xml $$i.txt; \
	done
	-for i in $(CRYPTS); do \
		$(RM) $$i.1.xml $$i.2.xml; \
	done
