pdfminer.six
============

[![Build Status](https://travis-ci.org/pdfminer/pdfminer.six.svg?branch=master)](https://travis-ci.org/pdfminer/pdfminer.six)
[![PyPI version](https://img.shields.io/pypi/v/pdfminer.six.svg)](https://pypi.python.org/pypi/pdfminer.six/)
[![gitter](https://badges.gitter.im/pdfminer-six/Lobby.svg)](https://gitter.im/pdfminer-six/Lobby?utm_source=badge&utm_medium)

Pdfminer.six is a community maintained fork of the original PDFMiner. It is a
tool for extracting information from PDF documents. It focuses on getting
and analyzing text data. Pdfminer.six extracts the text from a page directly
from the sourcecode of the PDF. It can also be used to get the exact location, 
font or color of the text. 

It is build in a modular way such that each component of pdfminer.six can be
replaced easily. You can implement your own interpreter or rendering device
to use the power of pdfminer.six for other purposes that text analysis. 

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
 * Support for RC4 and AES encryption.
 * Table of contents extraction.
 * Tagged contents extraction.
 * Automatic layout analysis.


How to use
----------

 * Install Python 3.4 or newer
 * Install

    `pip install pdfminer.six`

 * Use command-line interface to extract text from pdf:

    `python pdf2txt.py samples/simple1.pdf`


Contributing
------------

Be sure to read the [contribution guidelines](https://github.com/pdfminer/pdfminer.six/blob/master/CONTRIBUTING.md). 
