.. _api:

Get started using the high-level functions
******************************************

The high-level API can be used to do common tasks. Currently it contains a
single function `extract_text_to_fp` for reading text from a PDF file.

For example, to read text from a PDF and print it on the command line:

.. testsetup::

    from pdfminer.high_level import extract_text_to_fp

.. doctest::

    >>> from io import StringIO
    >>> output_string = StringIO()
    >>> with open('samples/simple1.pdf', 'rb') as fin:
    ...     extract_text_to_fp(fin, output_string)
    >>> print(output_string.getvalue().strip())
    Hello WorldHello WorldHello WorldHello World

Or to convert it to html and use layout analysis:

.. doctest::

    >>> from io import StringIO
    >>> from pdfminer.layout import LAParams
    >>> output_string = StringIO()
    >>> with open('samples/simple1.pdf', 'rb') as fin:
    ...     extract_text_to_fp(fin, output_string, laparams=LAParams(),
    ...                        output_type='html', codec=None)


API documentation
=================

extract_text_to_fp
------------------

.. currentmodule:: pdfminer.high_level
.. autofunction:: extract_text_to_fp
