# Makefile for pdfminer

DESTDIR=/usr/local/src/pdflib

PDFLIB = ${DESTDIR}/__init__.py \
	${DESTDIR}/arcfour.py \
	${DESTDIR}/ascii85.py \
	${DESTDIR}/cmap.py \
	${DESTDIR}/fontmetrics.py \
	${DESTDIR}/glyphlist.py \
	${DESTDIR}/latin_enc.py \
	${DESTDIR}/lzw.py \
	${DESTDIR}/pdf2txt.py \
	${DESTDIR}/pdfcolor.py \
	${DESTDIR}/pdfdevice.py \
	${DESTDIR}/pdffont.py \
	${DESTDIR}/pdfinterp.py \
	${DESTDIR}/pdfparser.py \
	${DESTDIR}/pdftypes.py \
	${DESTDIR}/psparser.py \
	${DESTDIR}/pycdb.py \
	${DESTDIR}/rijndael.py \
	${DESTDIR}/utils.py \

${DESTDIR}/%: %
	cp $? $@
	chmod 755 $@

all: ${PDFLIB}

clean:
	-rm *.pyc *.pyo
