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
        print('element                        font                  stroking color  text')
        print('------------------------------ --------------------- --------------  ----------')

    print(
        f'{get_indented_name(o, depth):<30.30s} '
        f'{get_optional_fontinfo(o):<20.20s} '
        f'{get_optional_color(o):<17.17s}'
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

def get_optional_color(o: Any) -> str:
    """Font info of LTChar if available, otherwise empty string"""
    if hasattr(o, 'graphicstate'):
        return f'{o.graphicstate.scolor}'
    return ''


def get_optional_text(o: Any) -> str:
    """Text of LTItem if available, otherwise empty string"""
    if hasattr(o, 'get_text'):
        return o.get_text().strip()
    return ''


path = Path('samples/simple1.pdf').expanduser()
pages = extract_pages(path)
show_ltitem_hierarchy(pages)
.. note::

The output looks like below. Note that it shows the hierarchical structure of the layout elements. The layout algorithm
groups characters into lines and lines into boxes. And boxes appear on a page. The pages, boxes and lines do not have
font information because this can change for each character. The stroking color is always `None` in this example, but
it will contain the color if the PDF does specify colors.

```
element                        font                  stroking color  text
------------------------------ --------------------- --------------  ----------
generator
  LTPage
    LTTextBoxHorizontal                                              Hello
      LTTextLineHorizontal                                           Hello
        LTChar                 Helvetica 24pt       None             H
        LTChar                 Helvetica 24pt       None             e
        LTChar                 Helvetica 24pt       None             l
        LTChar                 Helvetica 24pt       None             l
        LTChar                 Helvetica 24pt       None             o
        LTChar                 Helvetica 24pt       None
        LTAnno
    LTTextBoxHorizontal                                              World
      LTTextLineHorizontal                                           World
        LTChar                 Helvetica 24pt       None             W
        LTChar                 Helvetica 24pt       None             o
        LTChar                 Helvetica 24pt       None             r
        LTChar                 Helvetica 24pt       None             l
        LTChar                 Helvetica 24pt       None             d
        LTAnno
    LTTextBoxHorizontal                                              Hello
      LTTextLineHorizontal                                           Hello
        LTChar                 Helvetica 24pt       None             H
        LTChar                 Helvetica 24pt       None             e
        LTChar                 Helvetica 24pt       None             l
        LTChar                 Helvetica 24pt       None             l
        LTChar                 Helvetica 24pt       None             o
        LTChar                 Helvetica 24pt       None
        LTAnno
    LTTextBoxHorizontal                                              World
      LTTextLineHorizontal                                           World
        LTChar                 Helvetica 24pt       None             W
        LTChar                 Helvetica 24pt       None             o
        LTChar                 Helvetica 24pt       None             r
        LTChar                 Helvetica 24pt       None             l
        LTChar                 Helvetica 24pt       None             d
        LTAnno
    LTTextBoxHorizontal                                              H e l l o
      LTTextLineHorizontal                                           H e l l o
        LTChar                 Helvetica 24pt       None             H
        LTAnno
        LTChar                 Helvetica 24pt       None             e
        LTAnno
        LTChar                 Helvetica 24pt       None             l
        LTAnno
        LTChar                 Helvetica 24pt       None             l
        LTAnno
        LTChar                 Helvetica 24pt       None             o
        LTAnno
        LTChar                 Helvetica 24pt       None
        LTAnno
    LTTextBoxHorizontal                                              W o r l d
      LTTextLineHorizontal                                           W o r l d
        LTChar                 Helvetica 24pt       None             W
        LTAnno
        LTChar                 Helvetica 24pt       None             o
        LTAnno
        LTChar                 Helvetica 24pt       None             r
        LTAnno
        LTChar                 Helvetica 24pt       None             l
        LTAnno
        LTChar                 Helvetica 24pt       None             d
        LTAnno
    LTTextBoxHorizontal                                              H e l l o
      LTTextLineHorizontal                                           H e l l o
        LTChar                 Helvetica 24pt       None             H
        LTAnno
        LTChar                 Helvetica 24pt       None             e
        LTAnno
        LTChar                 Helvetica 24pt       None             l
        LTAnno
        LTChar                 Helvetica 24pt       None             l
        LTAnno
        LTChar                 Helvetica 24pt       None             o
        LTAnno
        LTChar                 Helvetica 24pt       None
        LTAnno
    LTTextBoxHorizontal                                              W o r l d
      LTTextLineHorizontal                                           W o r l d
        LTChar                 Helvetica 24pt       None             W
        LTAnno
        LTChar                 Helvetica 24pt       None             o
        LTAnno
        LTChar                 Helvetica 24pt       None             r
        LTAnno
        LTChar                 Helvetica 24pt       None             l
        LTAnno
        LTChar                 Helvetica 24pt       None             d
        LTAnno
```
