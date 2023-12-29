.. _char_properties:

How to extract font names and sizes from PDF's
******************************************************

Before you start, make sure you have :ref:`installed pdfminer.six<install>`.

The following code sample shows how to extract font names and sizes for each of the characters. This uses the
[simple1.pdf](https://raw.githubusercontent.com/pdfminer/pdfminer.six/master/samples/simple1.pdf).

.. code-block:: python
    from pathlib import Path
    from typing import Iterable, Any

    from pdfminer.high_level import extract_pages


    def show_ltitem_hierarchy(o: Any, depth=0):
        """Show location and text of LTItem and all its descendants"""
        if depth == 0:
            print('element                        fontname             text')
            print('------------------------------ -------------------- -----')

        print(
            f'{get_indented_name(o, depth):<30.30s} '
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


    def get_optional_text(o: Any) -> str:
        """Text of LTItem if available, otherwise empty string"""
        if hasattr(o, 'get_text'):
            return o.get_text().strip()
        return ''


    path = Path('simple1.pdf').expanduser()
    pages = extract_pages(path)
    show_ltitem_hierarchy(pages)
.. note::

The output looks like this.

```
element                        fontname             text
------------------------------ -------------------- -----
generator
  LTPage
    LTTextBoxHorizontal                             Hello
      LTTextLineHorizontal                          Hello
        LTChar                 Helvetica 24pt       H
        LTChar                 Helvetica 24pt       e
        LTChar                 Helvetica 24pt       l
        LTChar                 Helvetica 24pt       l
        LTChar                 Helvetica 24pt       o
        LTChar                 Helvetica 24pt
        LTAnno
    LTTextBoxHorizontal                             World
      LTTextLineHorizontal                          World
        LTChar                 Helvetica 24pt       W
        LTChar                 Helvetica 24pt       o
        LTChar                 Helvetica 24pt       r
        LTChar                 Helvetica 24pt       l
        LTChar                 Helvetica 24pt       d
        LTAnno
    LTTextBoxHorizontal                             Hello
      LTTextLineHorizontal                          Hello
        LTChar                 Helvetica 24pt       H
        LTChar                 Helvetica 24pt       e
        LTChar                 Helvetica 24pt       l
        LTChar                 Helvetica 24pt       l
        LTChar                 Helvetica 24pt       o
        LTChar                 Helvetica 24pt
        LTAnno
    LTTextBoxHorizontal                             World
      LTTextLineHorizontal                          World
        LTChar                 Helvetica 24pt       W
        LTChar                 Helvetica 24pt       o
        LTChar                 Helvetica 24pt       r
        LTChar                 Helvetica 24pt       l
        LTChar                 Helvetica 24pt       d
        LTAnno
    LTTextBoxHorizontal                             H e l l o
      LTTextLineHorizontal                          H e l l o
        LTChar                 Helvetica 24pt       H
        LTAnno
        LTChar                 Helvetica 24pt       e
        LTAnno
        LTChar                 Helvetica 24pt       l
        LTAnno
        LTChar                 Helvetica 24pt       l
        LTAnno
        LTChar                 Helvetica 24pt       o
        LTAnno
        LTChar                 Helvetica 24pt
        LTAnno
    LTTextBoxHorizontal                             W o r l d
      LTTextLineHorizontal                          W o r l d
        LTChar                 Helvetica 24pt       W
        LTAnno
        LTChar                 Helvetica 24pt       o
        LTAnno
        LTChar                 Helvetica 24pt       r
        LTAnno
        LTChar                 Helvetica 24pt       l
        LTAnno
        LTChar                 Helvetica 24pt       d
        LTAnno
    LTTextBoxHorizontal                             H e l l o
      LTTextLineHorizontal                          H e l l o
        LTChar                 Helvetica 24pt       H
        LTAnno
        LTChar                 Helvetica 24pt       e
        LTAnno
        LTChar                 Helvetica 24pt       l
        LTAnno
        LTChar                 Helvetica 24pt       l
        LTAnno
        LTChar                 Helvetica 24pt       o
        LTAnno
        LTChar                 Helvetica 24pt
        LTAnno
    LTTextBoxHorizontal                             W o r l d
      LTTextLineHorizontal                          W o r l d
        LTChar                 Helvetica 24pt       W
        LTAnno
        LTChar                 Helvetica 24pt       o
        LTAnno
        LTChar                 Helvetica 24pt       r
        LTAnno
        LTChar                 Helvetica 24pt       l
        LTAnno
        LTChar                 Helvetica 24pt       d
        LTAnno
```

