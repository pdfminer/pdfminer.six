.. _char_properties:

How to extract font names, sizes and colors from texts
******************************************************

Something to have in mind about the font name, size and color information of a
text block is that this is encoded at the character level. Therefore, we first
need to go down the layout hierarchy (see :ref:`topic_pdf_to_text`).

For example, if we wanted to extract these properties for an entire document, we
could use the following code:

.. code-block:: python

   from pdfminer.high_level import extract_pages
   from pdfminer.layout import LTTextBox, LTTextLine, LTChar


   doc = "..."

   fontnames, sizes, colors = [], [], []

   for page in extract_pages(doc):
       for element in page:
           if isinstance(element, LTTextBox):
               for line in element:
                   if isinstance(line, LTTextLine):
                       for char in line:
                           if isinstance(char, LTChar):
                               # Apparently, checking with ifs in every iteration
                               # is faster than working with sets.
                               if char.fontname not in fontnames:
                                   fontnames.append(char.fontname)
                               if char.size not in sizes:
                                   sizes.append(char.size)
                               if char.graphicstate.ncolor not in colors:
                                   colors.append(char.graphicstate.ncolor)

   print(fontnames)
   print(sizes)
   print(colors)

.. note::

   According to the `PDF Reference <https://www.adobe.com/go/pdfreference>`__,
   up to 11 different color spaces (see *8.6 Colour Spaces*) are supported.
   pdfminer.six will extract the color values as they are specified in the
   document. Therefore, these values could be a tuple with a single float
   (grayscale), a tuple with three values (RGB), a tuple with four values
   (CMYK), etc. The class :class:`pdfcolor.PDFColorSpace` lets you know the
   number of components a specific color space has. The color space of a
   character can be accessed via :obj:`LTChar.ncs`.
