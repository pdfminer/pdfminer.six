# GNUMakefile for test

RM=rm -f
CMP=:
PYTHON=python3
PDF2TXT=PYTHONPATH=../.. $(PYTHON) ../../tools/pdf2txt.py

XMLS= \
	rc4-40.xml \
	rc4-128.xml \
	aes-128.xml \
	aes-128-m.xml \
	aes-256.xml \
	aes-256-m.xml \

all: xmls

test:
	$(MAKE) all CMP=cmp

clean:
	-$(RM) $(XMLS)

xmls: $(XMLS)

.SUFFIXES: .pdf .xml

.pdf.xml:
	$(PDF2TXT) -p1 -V -t xml -P foo -o $@ $<
	$(CMP) $@ base.xml
	$(PDF2TXT) -p1 -V -t xml -P baz -o $@ $<
	$(CMP) $@ base.xml
