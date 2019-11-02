.. _commandline:

Get started with command-line tools
***********************************

pdfminer.six has several tools that can be used from the command line. The
command-line tools are aimed at users that occasionally want to extract text
from a pdf.

Take a look at the high-level or composable interface if you want to use
pdfminer.six programmatically.

Examples
========

pdf2txt.py
----------

::

    $ python tools/pdf2txt.py example.pdf
    all the text from the pdf appears on the command line

The pdf2txt.py tool extracts all the text from a PDF. It uses layout analysis
with sensible defaults to order and group the text in a sensible way.

dumppdf.py
----------

::

    $ python tools/dumppdf.py -a example.pdf
    <pdf><object id="1">
    ...
    </object>
    ...
    </pdf>

The dumppdf.py tool can be used to extract the internal structure from a PDF.
This tool is primarily for debugging purposes, but that can be useful to
anybody working with PDF's.


API documentation
=================

pdf2txt.py
----------

.. argparse::
    :module: tools.pdf2txt
    :func: maketheparser
    :prog: python tools/pdf2txt.py

dumppdf.py
----------

.. argparse::
    :module: tools.dumppdf
    :func: create_parser
    :prog: python tools/dumppdf.py
