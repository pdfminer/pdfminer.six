# Makefile for pdfminer

PYCHECKER=pychecker --limit=0

all:

clean:
	-rm *.pyc *.pyo
	cd cmap && make clean

check:
	$(PYCHECKER) *.py
