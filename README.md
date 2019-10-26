PDFMiner.six
============

PDFMiner.six is a fork of PDFMiner

[![Build Status](https://travis-ci.org/pdfminer/pdfminer.six.svg?branch=master)](https://travis-ci.org/pdfminer/pdfminer.six) [![PyPI version](https://img.shields.io/pypi/v/pdfminer.six.svg)](https://pypi.python.org/pypi/pdfminer.six/)

PDFMiner is a tool for extracting information from PDF documents.
Unlike other PDF-related tools, it focuses entirely on getting
and analyzing text data. PDFMiner allows one to obtain
the exact location of text in a page, as well as
other information such as fonts or lines.
It includes a PDF converter that can transform PDF files
into other text formats (such as HTML). It has an extensible
PDF parser that can be used for other purposes than text analysis.

 * Webpage: https://github.com/pdfminer/
 * Download (PyPI): https://pypi.python.org/pypi/pdfminer.six/


Features
--------

 * Written entirely in Python.
 * Parse, analyze, and convert PDF documents.
 * PDF-1.7 specification support. (well, almost).
 * CJK languages and vertical writing scripts support.
 * Various font types (Type1, TrueType, Type3, and CID) support.
 * Support for extracting images (JPG, JBIG2 and Bitmaps).
 * Basic encryption (RC4) support.
 * Outline (TOC) extraction.
 * Tagged contents extraction.
 * Automatic layout analysis.


How to Install
--------------

 * Install Python 3.4 or newer
 * Install

    `pip install pdfminer.six`

 * Run the following test:

    `pdf2txt.py samples/simple1.pdf`


Command Line Tools
------------------

PDFMiner comes with two handy tools:
pdf2txt.py and dumppdf.py.

**pdf2txt.py**

pdf2txt.py extracts text contents from a PDF file.
It extracts all the text that are to be rendered programmatically,
i.e. text represented as ASCII or Unicode strings.
It cannot recognize text drawn as images that would require optical character recognition.
It also extracts the corresponding locations, font names, font sizes, writing
direction (horizontal or vertical) for each text portion.
You need to provide a password for protected PDF documents when its access is restricted.
You cannot extract any text from a PDF document which does not have extraction permission.

(For details, refer to /docs/index.html.)

**dumppdf.py**

dumppdf.py dumps the internal contents of a PDF file in pseudo-XML format.
This program is primarily for debugging purposes,
but it's also possible to extract some meaningful contents (e.g. images).

(For details, refer to /docs/index.html.)


TODO
----

 * PEP-8 and PEP-257 conformance.
 * Better documentation.
 * Performance improvements.


Contributing
------------

Be sure to read the [contribution guidelines](https://github.com/pdfminer/pdfminer.six/blob/master/CONTRIBUTING.md). 
