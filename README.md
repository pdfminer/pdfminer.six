PDFMiner
==========

PDFMiner is a tool for extracting information from PDF documents.
Unlike other PDF-related tools, it focuses entirely on getting 
and analyzing text data. PDFMiner allows one to obtain
the exact location of text in a page, as well as 
other information such as fonts or lines.
It includes a PDF converter that can transform PDF files
into other text formats (such as HTML). It has an extensible
PDF parser that can be used for other purposes than text analysis.

**Features**

 * Written entirely in Python.
 * Parse, analyze, and convert PDF documents.
 * PDF-1.7 specification support. (well, almost)
 * CJK languages and vertical writing scripts support.
 * Various font types (Type1, TrueType, Type3, and CID) support.
 * Basic encryption (RC4) support.
 * Outline (TOC) extraction.
 * Tagged contents extraction.
 * Automatic layout analysis.

**How to Install**

 * Install Python 2.4 or newer. (**Python 3 is not supported.**)
 * Download the source code.
 * Unpack it.
 * Run `setup.py`:

    $ python setup.py install

 * Do the following test:

    $ pdf2txt.py samples/simple1.pdf

**For CJK Languages**

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
