PDFMiner
========

[![Build Status](https://travis-ci.org/euske/pdfminer.svg?branch=master)](https://travis-ci.org/euske/pdfminer)

PDFMiner is a tool for extracting information from PDF documents.
Unlike other PDF-related tools, it focuses entirely on getting 
and analyzing text data. PDFMiner allows one to obtain
the exact location of text in a page, as well as 
other information such as fonts or lines.
It includes a PDF converter that can transform PDF files
into other text formats (such as HTML). It has an extensible
PDF parser that can be used for other purposes than text analysis.

 * Webpage: https://euske.github.io/pdfminer/
 * Download (PyPI): https://pypi.python.org/pypi/pdfminer/
 * Demo WebApp: http://pdf2html.tabesugi.net:8080/


Features
--------

 * Written entirely in Python.
 * Parse, analyze, and convert PDF documents.
 * PDF-1.7 specification support. (well, almost)
 * CJK languages and vertical writing scripts support.
 * Various font types (Type1, TrueType, Type3, and CID) support.
 * Basic encryption (RC4) support.
 * Outline (TOC) extraction.
 * Tagged contents extraction.
 * Automatic layout analysis.


How to Install
--------------

 * Install Python 2.6 or newer. (**Python 3 is not supported.**)
 * Download the source code.
 * Unpack it.
 * Run `setup.py`:

    $ python setup.py install

 * Do the following test:

    $ pdf2txt.py samples/simple1.pdf


For CJK Languages
-----------------

In order to process CJK languages, do the following before
running setup.py install:

    $ make cmap
    python tools/conv_cmap.py pdfminer/cmap Adobe-CNS1 cmaprsrc/cid2code_Adobe_CNS1.txt
    reading 'cmaprsrc/cid2code_Adobe_CNS1.txt'...
    writing 'CNS1_H.py'...
    ...
    $ python setup.py install

On Windows machines which don't have `make` command, 
paste the following commands on a command line prompt:

    mkdir pdfminer\cmap
    python tools\conv_cmap.py -c B5=cp950 -c UniCNS-UTF8=utf-8 pdfminer\cmap Adobe-CNS1 cmaprsrc\cid2code_Adobe_CNS1.txt
    python tools\conv_cmap.py -c GBK-EUC=cp936 -c UniGB-UTF8=utf-8 pdfminer\cmap Adobe-GB1 cmaprsrc\cid2code_Adobe_GB1.txt
    python tools\conv_cmap.py -c RKSJ=cp932 -c EUC=euc-jp -c UniJIS-UTF8=utf-8 pdfminer\cmap Adobe-Japan1 cmaprsrc\cid2code_Adobe_Japan1.txt
    python tools\conv_cmap.py -c KSC-EUC=euc-kr -c KSC-Johab=johab -c KSCms-UHC=cp949 -c UniKS-UTF8=utf-8 pdfminer\cmap Adobe-Korea1 cmaprsrc\cid2code_Adobe_Korea1.txt
    python setup.py install


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

(For details, refer to the html document.)

**dumppdf.py**

dumppdf.py dumps the internal contents of a PDF file in pseudo-XML format. 
This program is primarily for debugging purposes,
but it's also possible to extract some meaningful contents (e.g. images).

(For details, refer to the html document.)


API Changes
-----------

As of November 2013, there were a few changes made to the PDFMiner API
prior to October 2013. This is the result of code restructuring.  Here
is a list of the changes:

 * PDFDocument class is moved to pdfdocument.py.
 * PDFDocument class now takes a PDFParser object as an argument.
   PDFDocument.set_parser() and PDFParser.set_document() is removed.
 * PDFPage class is moved to pdfpage.py
 * process_pdf function is implemented as a class method PDFPage.get_pages.


TODO
----

 * Replace STRICT variable with something better.
 * Use logging module instead of sys.stderr.
 * Proper test cases.
 * PEP-8 and PEP-257 conformance.
 * Better documentation.
 * Crypt stream filter support.


Related Projects
----------------

 * <a href="http://pybrary.net/pyPdf/">pyPdf</a>
 * <a href="http://www.foolabs.com/xpdf/">xpdf</a>
 * <a href="http://pdfbox.apache.org/">pdfbox</a>
 * <a href="http://mupdf.com/">mupdf</a>


Terms and Conditions
--------------------

(This is so-called MIT/X License)

Copyright (c) 2004-2014  Yusuke Shinyama <yusuke at cs dot nyu dot edu>

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
