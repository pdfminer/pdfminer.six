.. _tutorial_coordinates:

How to extract text, text coordinates and font information from a PDF
************************************************************************

The high-level API can be used to extract text, text coordinates and font information from a PDF.

pdfminer.six uses a Layout analysis algorithm which returns a hierarchical structure while 
extracting information from the PDF, the following example shows how you can traverse 
through the tree to extract information.

For more information on the Layout analysis algorithm, please refer to the
:ref:`topic_pdf_to_text_layout` section.

.. code-block:: python

    from pathlib import Path
    from typing import Iterable, Any

    from pdfminer.high_level import extract_pages

    def show_ltitem_hierarchy(o: Any, depth=0):
        """Show location and text of LTItem and all its descendants"""
        if depth == 0:
        print('element                         x1  y1  x2'
              '  y2  fontinfo             text')
        print('------------------------------ --- --- --- '
              '--- -------------------- -----')

        print(
            f'{get_indented_name(o, depth):<30.30s} '
            f'{get_optional_bbox(o)} '
            f'{get_optional_fontinfo(o):<20.20s} '
            f'{get_optional_text(o)}'
        )

        if isinstance(o, Iterable):
            for i in o:
                show_ltitem_hierarchy(i, depth=depth + 1)


    def get_indented_name(o: Any, depth: int) -> str:
        """Indented name of class"""
        return '  ' * depth + o.__class__.__name__


    def get_optional_fontinfo(o: Any) -> str:
        """Font info of LTChar if available, otherwise empty string"""
        if hasattr(o, 'fontname') and hasattr(o, 'size'):
            return f'{o.fontname} {round(o.size)}pt'
        return ''

    def get_optional_bbox(o: Any) -> str:
        """Bounding box of LTItem if available, otherwise empty string"""
        if hasattr(o, 'bbox'):
            return ''.join(f'{i:<4.0f}' for i in o.bbox)
        return ''

    def get_optional_text(o: Any) -> str:
        """Text of LTItem if available, otherwise empty string"""
        if hasattr(o, 'get_text'):
            return o.get_text().strip()
        return ''

    path = Path('~/Downloads/simple1.pdf').expanduser()
    pages = extract_pages(path)
    show_ltitem_hierarchy(pages)

You will get the following output:

.. doctest::

    element                         x1  y1  x2  y2  fontinfo             text
    ------------------------------ --- --- --- ---- -------------------- -----
    generator                                            
      LTPage                       0   0   612 792                       
        LTTextBoxHorizontal        100 695 161 719                       Hello
          LTTextLineHorizontal     100 695 161 719                       Hello
            LTChar                 100 695 117 719  Helvetica 24pt       H
            LTChar                 117 695 131 719  Helvetica 24pt       e
            LTChar                 131 695 136 719  Helvetica 24pt       l
            LTChar                 136 695 141 719  Helvetica 24pt       l
            LTChar                 141 695 155 719  Helvetica 24pt       o
            LTChar                 155 695 161 719  Helvetica 24pt       
            LTAnno                                       
        LTTextBoxHorizontal        261 695 324 719                       World
          LTTextLineHorizontal     261 695 324 719                       World
            LTChar                 261 695 284 719  Helvetica 24pt       W
            LTChar                 284 695 297 719  Helvetica 24pt       o
            LTChar                 297 695 305 719  Helvetica 24pt       r
            LTChar                 305 695 311 719  Helvetica 24pt       l
            LTChar                 311 695 324 719  Helvetica 24pt       d
            LTAnno  
    ...