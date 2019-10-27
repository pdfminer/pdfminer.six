Welcome to pdfminer.six's documentation!
========================================

.. image:: https://travis-ci.org/pdfminer/pdfminer.six.svg?branch=master
    :target: https://travis-ci.org/pdfminer/pdfminer.six
    :alt: build image

.. image:: https://img.shields.io/pypi/v/pdfminer.six.svg
    :target: https://pypi.python.org/pypi/pdfminer.six/
    :alt: PyPi version

pdfminer.six is a python package for extracting information from PDF documents.

* Source: https://github.com/pdfminer/pdfminer.six
* Documentation: https://pdfminersix.readthedocs.io/en/documentation/
* PyPI: https://pypi.python.org/pypi/pdfminer.six/


Content
-------

.. toctree::
    :maxdepth: 2

    usage


Features
--------

* Parse all objects from a PDF document into Python objects.
* Analyze and group text in a human-readable way.
* Extract text, images (JPG, JBIG2 and Bitmaps), table-of-contents, tagged
  contents and more.
* Support for (almost all) features from the PDF-1.7 specification
* Support for Chinese, Japanese and Korean CJK) languages as well as vertical
  writing.
* Support for various font types (Type1, TrueType, Type3, and CID).
* Support for basic encryption (RC4).


Getting started
---------------

pdfminer.six can be used on the command line, using the high-level API
or using the composable API. But, before using it, you must install it
using Python 2.7 or newer.

::

    $ pip install pdfminer.six

Note that Python 2.7 support is dropped at January, 2020.

Use command line tools
######################

pdfminer.six has several tools that can be used from the command line.

pdf2txt.py
^^^^^^^^^^

::

    $ python tools/pdf2txt.py example.pdf
    all the text from the pdf appears on the command line

The pdf2txt.py tool extracts all the text from a PDF. It uses layout analysis
with sensible defaults to order and group the text in a sensible way.

Also see :ref:`pdf2txt`

dumppdf.py
^^^^^^^^^^

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

Also see :ref:`dumppdf`


Use high-level API
##################

The command line tool pdf2txt.py is just a wrapper around the high-level API
of pdfminer.six. It currently consists of only a single method.

::
    from pdfminer.high_level import extract_text_to_fp
    from pdfminer.layout import LAParams

    with open('samples/simple1.pdf', 'rb') as pdf_file:
        with open('output_file.txt', 'w') as output_file:
            extract_text_to_fp(pdf_file, output_file, laparams=LAParams())

Also see :ref:`api`


Use composable API
##################

The command line tools and the high-level API are just shortcuts for often
used combinations of pdfminer.six components. You can use these components to
modify pdfminer.six to your own needs.

For example, to extract the text from a PDF file and save it in a python
variable::

    from io import StringIO

    from pdfminer.converter import TextConverter
    from pdfminer.layout import LAParams
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
    from pdfminer.pdfpage import PDFPage
    from pdfminer.pdfparser import PDFParser

    output_string = StringIO()
    with open('samples/simple1.pdf', 'rb') as in_file:
        parser = PDFParser(in_file)
        doc = PDFDocument(parser)
        rsrcmgr = PDFResourceManager()
        device = TextConverter(rsrcmgr, output_string, laparams=LAParams())
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        for page in PDFPage.create_pages(doc):
            interpreter.process_page(page)

    print(output_string.getvalue())

Also see :ref:`composable`


Contributing
------------

We welcome any contributors to pdfminer.six! But, before doing anything, take
a look at the `contribution guide <https://github.com/pdfminer/pdfminer.six/blob/master/CONTRIBUTING.md>`_.
