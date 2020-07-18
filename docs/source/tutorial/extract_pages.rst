.. _tutorial_extract_pages:

Extract elements from a PDF using Python
****************************************

The high level functions can be used to achieve common tasks. In this case,
we can use :ref:`api_extract_pages`:

.. code-block:: python

   from pdfminer.high_level import extract_pages
   for page_layout in extract_pages("test.pdf"):
       for element in page_layout:
           print(element)


Each ``element`` will be an ``LTTextBox``, ``LTFigure``, ``LTLine``, ``LTRect``
or an ``LTImage``. Some of these can be iterated further, for example iterating
though an ``LTTextBox`` will give you an ``LTTextLine``, and these in turn can
be iterated through to get an ``LTChar``. See the diagram here:
:ref:`topic_pdf_to_text_layout`.

Let's say we want to extract all of the text. We could do:

.. code-block:: python

   from pdfminer.high_level import extract_pages
   from pdfminer.layout import LTTextContainer
   for page_layout in extract_pages("test.pdf"):
       for element in page_layout:
           if isinstance(element, LTTextContainer):
               print(element.get_text())

Or, we could extract the fontname or size of each individual character:

.. code-block:: python

   from pdfminer.high_level import extract_pages
   from pdfminer.layout import LTTextContainer, LTChar
   for page_layout in extract_pages("test.pdf"):
       for element in page_layout:
           if isinstance(element, LTTextContainer):
               for text_line in element:
                   for character in text_line:
                       if isinstance(character, LTChar):
                           print(character.fontname)
                           print(character.size)
