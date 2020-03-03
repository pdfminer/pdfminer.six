.. testsetup::

    import sys
    from pdfminer.high_level import extract_text_to_fp, extract_text

.. _tutorial_highlevel:

Get started using the high-level functions
******************************************

The high-level API can be used to do common tasks.

The most simple way to extract text from a PDF is to use
:ref:`api_extract_text`:

.. doctest::

    >>> text = extract_text('samples/simple1.pdf')
    >>> print(repr(text))
    'Hello \n\nWorld\n\nHello \n\nWorld\n\nH e l l o  \n\nW o r l d\n\nH e l l o  \n\nW o r l d\n\n\x0c'
    >>> print(text)
    ... # doctest: +NORMALIZE_WHITESPACE
    Hello
    <BLANKLINE>
    World
    <BLANKLINE>
    Hello
    <BLANKLINE>
    World
    <BLANKLINE>
    H e l l o
    <BLANKLINE>
    W o r l d
    <BLANKLINE>
    H e l l o
    <BLANKLINE>
    W o r l d
    <BLANKLINE>


To read text from a PDF and print it on the command line:

.. doctest::

    >>> if sys.version_info > (3, 0):
    ...     from io import StringIO
    ... else:
    ...     from io import BytesIO as StringIO
    >>> output_string = StringIO()
    >>> with open('samples/simple1.pdf', 'rb') as fin:
    ...     extract_text_to_fp(fin, output_string)
    >>> print(output_string.getvalue().strip())
    Hello WorldHello WorldHello WorldHello World

Or to convert it to html and use layout analysis:

.. doctest::

    >>> if sys.version_info > (3, 0):
    ...     from io import StringIO
    ... else:
    ...     from io import BytesIO as StringIO
    >>> from pdfminer.layout import LAParams
    >>> output_string = StringIO()
    >>> with open('samples/simple1.pdf', 'rb') as fin:
    ...     extract_text_to_fp(fin, output_string, laparams=LAParams(),
    ...                        output_type='html', codec=None)
