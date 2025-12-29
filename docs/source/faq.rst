.. _faq:

Frequently asked questions
**************************

Why is it called pdfminer.six?
==============================

Pdfminer.six is a fork of the `original pdfminer created by Euske
<https://github.com/euske>`_. Almost all of the code and architecture are in
-fact created by Euske. But, for a long time, this original pdfminer did not
support Python 3. Until 2020 the original pdfminer only supported Python 2.
The original goal of pdfminer.six was to add support for Python 3. This was
done with the `six` package. The `six` package helps to write code that is
compatible with both Python 2 and Python 3. Hence, pdfminer.six.

As of 2020, pdfminer.six dropped the support for Python 2 because it was
`end-of-life <https://www.python.org/doc/sunset-python-2/>`_. While the .six
part is no longer applicable, we kept the name to prevent breaking changes for
existing users.

The current punchline "We fathom PDF" is a `whimsical reference
<https://github.com/pdfminer/pdfminer.six/issues/197#issuecomment-655091942>`_
to the six. Fathom means both deeply understanding something, and a fathom is
also equal to six feet.

How does pdfminer.six compare to other forks of pdfminer?
==========================================================

Pdfminer.six is now an independent and community-maintained package for
extracting text from PDFs with Python. We actively fix bugs (also for PDFs
that don't strictly follow the PDF Reference), add new features and improve
the usability of pdfminer.six. This community separates pdfminer.six from the
other forks of the original pdfminer. PDF as a format is very diverse and
there are countless deviations from the official format. The only way to
support all the PDFs out there is to have a community that actively uses and
improves pdfminer.

Since 2020, the original pdfminer is `dormant
<https://github.com/euske/pdfminer#pdfminer>`_, and pdfminer.six is the fork
which Euske recommends if you need an actively maintained version of pdfminer.

Why are there `(cid:x)` values in the textual output?
=====================================================

One of the most common issues with pdfminer.six is that the textual output
contains raw character id's `(cid:x)`. This is often experienced as confusing
because the text is shown fine in a PDF viewer and other text from the same
PDF is extracted properly.

The underlying problem is that a PDF has two different representations
of each character. Each character is mapped to a glyph that determines
how the character is shown in a PDF viewer. And each character is also
mapped to its unicode value that is used when copy-pasting the character.
Some PDF's have incomplete unicode mappings and therefore it is impossible
to convert the character to unicode. In these cases pdfminer.six defaults
to showing the raw character id `(cid:x)`

A quick test to see if pdfminer.six should be able to do better is to
copy-paste the text from a PDF viewer to a text editor. If the result
is proper text, pdfminer.six should also be able to extract proper text.
If the result is gibberish, pdfminer.six will also not be able to convert
the characters to unicode.

References:

#. `Chapter 5: Text, PDF Reference 1.7 <https://opensource.adobe.com/dc-acrobat-sdk-docs/pdflsdk/index.html#pdf-reference>`_
#. `Text: PDF, Wikipedia <https://en.wikipedia.org/wiki/PDF#Text>`_
