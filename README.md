Pdfminer.six
============

[![Build Status](https://travis-ci.org/pdfminer/pdfminer.six.svg?branch=master)](https://travis-ci.org/pdfminer/pdfminer.six)
[![PyPI version](https://img.shields.io/pypi/v/pdfminer.six.svg)](https://pypi.python.org/pypi/pdfminer.six/)
[![gitter](https://badges.gitter.im/pdfminer-six/Lobby.svg)](https://gitter.im/pdfminer-six/Lobby?utm_source=badge&utm_medium)

Pdfminer.six is an community maintained fork of the original PDFMiner. It is a
tool for extracting information from PDF documents.
Unlike other PDF-related tools, it focuses entirely on getting
and analyzing text data. Pdfminer.six allows one to obtain
the exact location of text in a page, as well as
other information such as fonts or lines.
It includes a PDF converter that can transform PDF files
into other text formats (such as HTML). It has an extensible
PDF parser that can be used for other purposes than text analysis.

Check out the full documentation on
[Read the Docs](https://pdfminersix.readthedocs.io).


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


How to use
----------

 * Install Python 2.7 or newer. Note that Python 2 support is dropped at
  January, 2020.

    `pip install pdfminer.six`

 * Use command-line interface to extract text from pdf:

    `python pdf2txt.py samples/simple1.pdf`
    
* Check out more examples and documentation on
[Read the Docs](https://pdfminersix.readthedocs.io).


Contributing
------------

Be sure to read the [contribution guidelines](https://github.com/pdfminer/pdfminer.six/blob/master/CONTRIBUTING.md). 
