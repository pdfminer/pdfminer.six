Welcome to pdfminer.six's documentation!
****************************************

.. image:: https://travis-ci.org/pdfminer/pdfminer.six.svg?branch=master
    :target: https://travis-ci.org/pdfminer/pdfminer.six
    :alt: Travis-ci build badge

.. image:: https://img.shields.io/pypi/v/pdfminer.six.svg
    :target: https://pypi.python.org/pypi/pdfminer.six/
    :alt: PyPi version badge

.. image:: https://badges.gitter.im/pdfminer-six/Lobby.svg
    :target: https://gitter.im/pdfminer-six/Lobby?utm_source=badge&utm_medium
    :alt: gitter badge

We fathom PDF.

Pdfminer.six is a python package for extracting information from PDF documents.

Check out the source on `github <https://github.com/pdfminer/pdfminer.six>`_.

Content
=======

This documentation is organized into four sections (according to the `Diátaxis
documentation framework <https://diataxis.fr>`_). The
:ref:`tutorial` section helps you setup and use pdfminer.six for the first
time. Read this section if this is your first time working with pdfminer.six.
The :ref:`howto` offers specific recipes for solving common problems.
Take a look at the :ref:`topic` if you want more background information on
how pdfminer.six works internally. The :ref:`reference` provides
detailed api documentation for all the common classes and functions in
pdfminer.six.

.. toctree::
    :maxdepth: 2

    tutorial/index
    howto/index
    topic/index
    reference/index
    faq


Features
========

* Parse all objects from a PDF document into Python objects.
* Analyze and group text in a human-readable way.
* Extract text, images (JPG, JBIG2 and Bitmaps), table-of-contents, tagged
  contents and more.
* Support for (almost all) features from the PDF-1.7 specification
* Support for Chinese, Japanese and Korean CJK) languages as well as vertical writing.
* Support for various font types (Type1, TrueType, Type3, and CID).
* Support for RC4 and AES encryption.
* Support for AcroForm interactive form extraction.


Installation instructions
=========================

* Install Python 3.10 or newer.
* Install pdfminer.six.

::
    $ pip install pdfminer.six`

* (Optionally) install extra dependencies for extracting images.

::
    $ pip install 'pdfminer.six[image]'`

* Use the command-line interface to extract text from pdf.

::
    $ pdf2txt.py example.pdf`

* Or use it with Python.

.. code-block:: python

    from pdfminer.high_level import extract_text

    text = extract_text("example.pdf")
    print(text)



Contributing
============

We welcome any contributors to pdfminer.six! But, before doing anything, take
a look at the `contribution guide
<https://github.com/pdfminer/pdfminer.six/blob/master/CONTRIBUTING.md>`_.
