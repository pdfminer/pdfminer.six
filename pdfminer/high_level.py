# -*- coding: utf-8 -*-
"""
Functions that encapsulate "usual" use-cases for pdfminer, for use making
bundled scripts and for using pdfminer as a module for routine tasks.
"""

import six
import sys

from .pdfdocument import PDFDocument
from .pdfparser import PDFParser
from .pdfinterp import PDFResourceManager, PDFPageInterpreter
from .pdfdevice import PDFDevice, TagExtractor
from .pdfpage import PDFPage
from .converter import XMLConverter, HTMLConverter, TextConverter
from .cmapdb import CMapDB
from .image import ImageWriter


def extract_text_to_fp(inf, outfp,
                    _py2_no_more_posargs=None,  # Bloody Python2 needs a shim
                    output_type='text', codec='utf-8', laparams = None,
                    maxpages=0, page_numbers=None, password="", scale=1.0, rotation=0,
                    layoutmode='normal', output_dir=None, strip_control=False,
                    debug=False, disable_caching=False, **other):
    """
    Parses text from inf-file and writes to outfp file-like object.
    Takes loads of optional arguments but the defaults are somewhat sane.
    Beware laparams: Including an empty LAParams is not the same as passing None!
    Returns nothing, acting as it does on two streams. Use StringIO to get strings.
    
    output_type: May be 'text', 'xml', 'html', 'tag'. Only 'text' works properly.
    codec: Text decoding codec
    laparams: An LAParams object from pdfminer.layout.
        Default is None but may not layout correctly.
    maxpages: How many pages to stop parsing after
    page_numbers: zero-indexed page numbers to operate on.
    password: For encrypted PDFs, the password to decrypt.
    scale: Scale factor
    rotation: Rotation factor
    layoutmode: Default is 'normal', see pdfminer.converter.HTMLConverter
    output_dir: If given, creates an ImageWriter for extracted images.
    strip_control: Does what it says on the tin
    debug: Output more logging data
    disable_caching: Does what it says on the tin
    """
    if six.PY2 and sys.stdin.encoding:
        password = password.decode(sys.stdin.encoding)

    imagewriter = None
    if output_dir:
        imagewriter = ImageWriter(output_dir)
    
    rsrcmgr = PDFResourceManager(caching=not disable_caching)

    if output_type == 'text':
        device = TextConverter(rsrcmgr, outfp, codec=codec, laparams=laparams,
                               imagewriter=imagewriter)

    if six.PY3 and outfp == sys.stdout:
        outfp = sys.stdout.buffer

    if output_type == 'xml':
        device = XMLConverter(rsrcmgr, outfp, codec=codec, laparams=laparams,
                              imagewriter=imagewriter,
                              stripcontrol=strip_control)
    elif output_type == 'html':
        device = HTMLConverter(rsrcmgr, outfp, codec=codec, scale=scale,
                               layoutmode=layoutmode, laparams=laparams,
                               imagewriter=imagewriter)
    elif output_type == 'tag':
        device = TagExtractor(rsrcmgr, outfp, codec=codec)

    interpreter = PDFPageInterpreter(rsrcmgr, device)
    for page in PDFPage.get_pages(inf,
                                  page_numbers,
                                  maxpages=maxpages,
                                  password=password,
                                  caching=not disable_caching,
                                  check_extractable=True):
        page.rotate = (page.rotate + rotation) % 360
        interpreter.process_page(page)    

    device.close()
