"""Functions that can be used for the most common use-cases for pdfminer.six"""

import logging
import sys
from io import StringIO

from .converter import XMLConverter, HTMLConverter, TextConverter, \
    PDFPageAggregator
from .image import ImageWriter
from .layout import LAParams
from .pdfdevice import TagExtractor
from .pdfinterp import PDFResourceManager, PDFPageInterpreter
from .pdfpage import PDFPage


def extract_text_to_fp(inf, outfp, output_type='text', codec='utf-8',
                       laparams=None, maxpages=0, page_numbers=None,
                       password="", scale=1.0, rotation=0, layoutmode='normal',
                       output_dir=None, strip_control=False, debug=False,
                       disable_caching=False, **kwargs):
    """Parses text from inf-file and writes to outfp file-like object.

    Takes loads of optional arguments but the defaults are somewhat sane.
    Beware laparams: Including an empty LAParams is not the same as passing
        None!

    :param inf: a file-like object to read PDF structure from, such as a
        file handler (using the builtin `open()` function) or a `BytesIO`.
    :param outfp: a file-like object to write the text to.
    :param output_type: May be 'text', 'xml', 'html', 'tag'. Only 'text' works
        properly.
    :param codec: Text decoding codec
    :param laparams: An LAParams object from pdfminer.layout. Default is None
        but may not layout correctly.
    :param maxpages: How many pages to stop parsing after
    :param page_numbers: zero-indexed page numbers to operate on.
    :param password: For encrypted PDFs, the password to decrypt.
    :param scale: Scale factor
    :param rotation: Rotation factor
    :param layoutmode: Default is 'normal', see
        pdfminer.converter.HTMLConverter
    :param output_dir: If given, creates an ImageWriter for extracted images.
    :param strip_control: Does what it says on the tin
    :param debug: Output more logging data
    :param disable_caching: Does what it says on the tin
    :param other:
    :return: nothing, acting as it does on two streams. Use StringIO to get
        strings.
    """
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    imagewriter = None
    if output_dir:
        imagewriter = ImageWriter(output_dir)

    rsrcmgr = PDFResourceManager(caching=not disable_caching)

    if output_type == 'text':
        device = TextConverter(rsrcmgr, outfp, codec=codec, laparams=laparams,
                               imagewriter=imagewriter)

    if outfp == sys.stdout:
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


def extract_text(pdf_file, password='', page_numbers=None, maxpages=0,
                 caching=True, codec='utf-8', laparams=None):
    """Parse and return the text contained in a PDF file.

    :param pdf_file: Path to the PDF file to be worked on
    :param password: For encrypted PDFs, the password to decrypt.
    :param page_numbers: List of zero-indexed page numbers to extract.
    :param maxpages: The maximum number of pages to parse
    :param caching: If resources should be cached
    :param codec: Text decoding codec
    :param laparams: An LAParams object from pdfminer.layout. If None, uses
        some default settings that often work well.
    :return: a string containing all of the text extracted.
    """
    if laparams is None:
        laparams = LAParams()

    with open(pdf_file, "rb") as fp, StringIO() as output_string:
        rsrcmgr = PDFResourceManager()
        device = TextConverter(rsrcmgr, output_string, codec=codec,
                               laparams=laparams)
        interpreter = PDFPageInterpreter(rsrcmgr, device)

        for page in PDFPage.get_pages(
                fp,
                page_numbers,
                maxpages=maxpages,
                password=password,
                caching=caching,
                check_extractable=True,
        ):
            interpreter.process_page(page)

        return output_string.getvalue()


def extract_pages(pdf_file, password='', page_numbers=None, maxpages=0,
                  caching=True, laparams=None):
    """Extract and yield LTPage objects

    :param pdf_file: Path to the PDF file to be worked on
    :param password: For encrypted PDFs, the password to decrypt.
    :param page_numbers: List of zero-indexed page numbers to extract.
    :param maxpages: The maximum number of pages to parse
    :param caching: If resources should be cached
    :param laparams: An LAParams object from pdfminer.layout. If None, uses
        some default settings that often work well.
    :return:
    """
    if laparams is None:
        laparams = LAParams()

    with open(pdf_file, "rb") as fp:
        resource_manager = PDFResourceManager()
        device = PDFPageAggregator(resource_manager, laparams=laparams)
        interpreter = PDFPageInterpreter(resource_manager, device)
        for page in PDFPage.get_pages(fp, page_numbers, maxpages=maxpages,
                                      password=password, caching=caching):
            interpreter.process_page(page)
            layout = device.get_result()
            yield layout

 def lrtd_parse_page(document,callback,context):
    """Parse page and yield text token left to right and top down (lrtd)
    
    :param document: open stream to the PDF file to be worked on
    :param callback: a function to callback each tim a page is processed accept 3 parameters 
         p the page, starts at 0 
         selts the lrtb token list and context.
         selts is a list of objects {"x1":x1,"y1":y1,"x0":x0,"y0":y0,"txt":text}
         (x0,y0),(x1,y1) are the coordinates of the box surrounding the object
    :param context: a caller context object for storing some data and passed to callback
    """
    rsrcmgr = PDFResourceManager()
    laparams = LAParams()
    device = PDFPageAggregator(rsrcmgr, laparams=laparams)
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    i=0
    p=0
    for page in PDFPage.get_pages(document):
            interpreter.process_page(page)
            layout = device.get_result()
            elts=[]
            m = 0
            mindelatheight = 1000
            for element in layout:
                if isinstance(element, LTTextBoxHorizontal):
                    x0 = element.x0
                    y0 = element.y0
                    x1 = element.x1
                    y1 = element.y1
                    lines = element.get_text().splitlines()
                    lenlines = len(lines)
                    j = 0
                    deltaheight = (y1-y0)/lenlines
                    if mindeltaheight > deltaheight:
                        mindeltaheight = deltaheight
                    for line in lines:
                        x0j = x0
                        y0j = y1 - (1+j)*deltaheight
                        x1j = x1
                        y1j = y1 - j*deltaheight
                        j += 1
                        elts.append({"x1":x1j,"y1":y1j,"x0":x0j,"y0":y0j,"txt":line})
                    if m < element.y1:
                        m = element.y1
            n = len(elts)
            elts1 = []
            for i in range(1,n):
                for j in range(i+1,n):
                    if abs(elts[i-1]["y0"]-elts[j-1]["y0"])<(mindeltaheight/2):
                        elts[j-1]["y0"] = elts[i-1]["y0"]
                    if abs(elts[i-1]["y1"]-elts[j-1]["y1"])<(mindeltaheight/2):
                        elts[j-1]["y1"] = elts[i-1]["y1"]
                    
            selts = sorted(elts, key=lambda item: (round((2*m-item['y0']-item['y1'])/2,0),round(item['x0'],0)))   
            
            # for elt in selts:
            #    print(f"({p})({elt['x0']:0.0f},{elt['y0']:0.0f},{elt['x1']:0.0f},{elt['y1']:0.0f}){elt['txt']}")
            if not callback(p,selts,context):
                return
                
            p +=1
