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


Pdfminer.six is a python package for extracting information from PDF documents.

Check out the source on `github <https://github.com/pdfminer/pdfminer.six>`_.

Content
=======

.. toctree::
    :maxdepth: 2

    tutorials/index
    api/index
    topics/index


Features
========

* Parse all objects from a PDF document into Python objects.
* Analyze and group text in a human-readable way.
* Extract text, images (JPG, JBIG2 and Bitmaps), table-of-contents, tagged
  contents and more.
* Support for (almost all) features from the PDF-1.7 specification
* Support for Chinese, Japanese and Korean CJK) languages as well as vertical
  writing.
* Support for various font types (Type1, TrueType, Type3, and CID).
* Support for basic encryption (RC4).


Installation instructions
=========================

Before using it, you must install it using Python 2.7 or newer.

::

    $ pip install pdfminer.six

Note that Python 2.7 support is dropped at January, 2020.

Common use-cases
----------------

* :ref:`tutorial_commandline` if you just want to extract text from a pdf once.
* :ref:`tutorial_highlevel` if you want to integrate pdfminer.six with your
  Python code.
* :ref:`tutorial_composable` when you want to tailor the behavior of
  pdfmine.six to your needs.


Contributing
============

We welcome any contributors to pdfminer.six! But, before doing anything, take
a look at the `contribution guide
<https://github.com/pdfminer/pdfminer.six/blob/master/CONTRIBUTING.md>`_.
