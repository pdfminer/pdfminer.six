.. _topic_pdf_to_text:

Converting a PDF file to text
*****************************

Most PDF files look like they contain well structured text. But the reality  is
that a PDF file does not contain anything that resembles a paragraphs,
sentences or even words. When it comes to text, a PDF file is only aware of
the characters and their placement.

This makes extracting meaningful pieces of text from PDF's files difficult.
The characters that compose a paragraph are no different from those that
compose the table, the page footer or the description of a figure. Unlike
other documents formats, like a `.txt` file or a word document, the PDF format
does not contain a stream of text.

A PDF document does consists of a collection of objects that together describe
the appearance of one or more pages, possibly accompanied by additional
interactive elements and higher-level application data. A PDF file contains
the objects making up a PDF document along with associated structural
information, all represented as a single self-contained sequence of bytes. [1]_

Layout analysis
===============

PDFMiner attempts to reconstruct some of those structures by using heuristics
on the positioning of characters. This works well for sentences and
paragraphs because meaningful groups of nearby characters can be made.

The layout analysis consist of three different stages: it groups characters
into words and lines, then it groups lines into boxes and finally it groups
textboxes hierarchically. These stages are discussed in the following
sections.  The resulting output of the layout analysis is an ordered hierarchy
of layout objects on a PDF page.

.. figure:: ../_static/layout_analysis_output.png
    :align: center

    The output of the layout analysis is a hierarchy of layout objects.

Grouping characters into words and lines
----------------------------------------

The first step in going from characters to text is to group characters in a
meaningful way. Each character has an x-coordinate and a y-coordinate for its
bottom-left corner and upper-right corner, i.e. its bounding box.  pdfminer
.six uses these bounding boxes to decide which characters belong together.

Characters that are both horizontally and vertically close are grouped. How
close they should be is determined by the `char_margin` (M in figure) and the
`line_overlap` (not in figure) parameter. The horizontal *distance* between the
bounding boxes of two characters should be smaller that the `char_margin` and
the vertical *overlap* between the bounding boxes should be smaller the the
`line_overlap`.


.. raw:: html
    :file: ../_static/layout_analysis.html

The values of `char_margin` and `line_overlap` are relative to the size of
the bounding boxes of the characters. The `char_margin` is relative to the
maximum width of either one of the bounding boxes, and the `line_overlap` is
relative to the minimum height of either one of the bounding boxes.

Spaces need to be inserted between characters because the PDF format has no
notion of the space character. A space is inserted if the characters are
further apart that the `word_margin` (W in the figure). The `word_margin` is
relative to the maximum width or height of the new character. Having a larger
`word_margin` creates smaller words and inserts spaces between characters
more often. Note that the `word_margin` should be smaller than the
`char_margin` otherwise all the characters are seperated by a space.

Grouping lines into boxes
-------------------------

Grouping textboxes hierarchically
---------------------------------


References
==========

.. [1] Adobe System Inc. (2007). *Pdf reference: Adobe portable document
  format, version 1.7.*
