#!/usr/bin/env python
"""
Converts PDF text content (though not images containing text) to plain text, html, xml or "tags".
"""
import sys
import logging
import six

from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.pdfdevice import PDFDevice, TagExtractor
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import XMLConverter, HTMLConverter, TextConverter
from pdfminer.cmapdb import CMapDB
from pdfminer.layout import LAParams
from pdfminer.image import ImageWriter


def _check_arg():
    """
    Type-checking the ugly way, because we can't do arg annotations and reflection
    in Python 2.
    """
    arg = locals()[arg_name]
    assert isinstance(arg, arg_permitted), ("Argument '{}' should be of type(s)"
            " '{}' but is type '{}'").format(arg_name, arg_permitted, type(arg))
    if contains_permitted is not None and arg:
        for contained in arg:
            assert isinstance(contained, contains_permitted), ("Value within"
                    " argument '{}' should be of type '{}' but is '{}'"
                    ).format(arg_name, contains_permitted, type(contained))

def extract_text_to_fp(inf, outfp,
                    output_type='text', codec='utf-8', laparams = None,
                    maxpages=0, page_numbers=None, password="", scale=1.0, rotation=0,
                    layoutmode='normal', output_dir=None, strip_control=False,
                    debug=False, disable_caching=False, **other):
    """
    Parses text from inf-file and writes to outfp file-like object.
    Takes loads of optional arguments but the defaults are somewhat sane.
    Beware laparams: Including an empty LAParams is not the same as passing None!
    Returns nothing, acting as it does on two streams. Use StringIO to get strings.
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
    

def extract_text(files=[], outfile='-',
                     _py2_no_more_posargs=None,  # Bloody Python2 users need a shim for mandatory keyword args..
                     output_type='text', codec='utf-8', maxpages=0, page_numbers=None, password="", scale=1.0,
                     all_texts=None, detect_vertical=None, word_margin=None, char_margin=None, line_margin=None, boxes_flow=None, # LAParams
                     debug=False, layoutmode='normal', no_laparams=False, rotation=0, output_dir=None,
                     disable_caching=False, strip_control=False, pagenos=None):
    if _py2_no_more_posargs is not None:
        raise ValueError("Too many positional arguments passed.")
    if not files:
        raise ValueError("Must provide files to work upon!")

    # == Typechecking ==
    # You can be sure for this many arguments that typechecking will catch errors.
    # Yet more Py2 stupidity, should be able to use argument annotations to do
    # type-checking cleanly, but can't. Not bothering to typecheck everything here.
    if debug:
        for arg_name, arg_permitted, contains_permitted in (
                    ("files", list, str),
                    ("outfile", str, None),
                    ("password", str, None),
                    ("scale", float, None),
                    ("output_type", str, None),
                    ("codec", str, None),
                    ("maxpages", int, None),
                    ("page_numbers", (type(None), list, set), int)
                ):
            arg = locals()[arg_name]
            assert isinstance(arg, arg_permitted), ("Argument '{}' should be of type(s)"
                    " '{}' but is type '{}'").format(arg_name, arg_permitted, type(arg))
            if contains_permitted is not None and arg:
                for contained in arg:
                    assert isinstance(contained, contains_permitted), ("Value within"
                            " argument '{}' should be of type '{}' but is '{}'"
                            ).format(arg_name, contains_permitted, type(contained))
    # == Typechecking over ==    

    # If any LAParams group arguments were passed, create an LAParams object and
    # populate with given args. Otherwise, set it to None.
    if not no_laparams: 
        laparams = LAParams()
        for param in ("all_texts", "detect_vertical", "word_margin", "char_margin", "line_margin", "boxes_flow"):
            paramv = locals().get(param, None)
            if paramv is not None:
                setattr(laparams, param, paramv)
    else:
        laparams = None

    imagewriter = None
    if output_dir:
        imagewriter = ImageWriter(output_dir)

    if six.PY2 and sys.stdin.encoding:
        password = password.decode(sys.stdin.encoding)
    
    if output_type == "text" and outfile != "-":
        for override, alttype in (  (".htm", "html"),
                                    (".html", "html"),
                                    (".xml", "xml"),
                                    (".tag", "tag") ):
            if outfile.endswith(override):
                output_type = alttype
    
    if outfile == "-":
        outfp = sys.stdout
        if outfp.encoding is not None:
            codec = 'utf-8'
    else:
        outfp = open(outfile, "wb")
    
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

    for fname in files:
        with open(fname, "rb") as fp:
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            for page in PDFPage.get_pages(fp,
                                          page_numbers,
                                          maxpages=maxpages,
                                          password=password,
                                          caching=not disable_caching,
                                          check_extractable=True):
                page.rotate = (page.rotate + rotation) % 360
                interpreter.process_page(page)
    device.close()
    return outfp

# main
def main(args=None):
    import argparse
    P = argparse.ArgumentParser(description=__doc__)
    P.add_argument("files", type=str, default=None, nargs="+", help="Files to process.")
    P.add_argument("-d", "--debug", default=False, action="store_true", help="Debug output.")
    P.add_argument("-p", "--pagenos", type=str, help="Comma-separated list of page numbers to parse. Included for legacy applications, use -P/--page-numbers for more idiomatic argument entry.")
    P.add_argument("--page-numbers", type=int, default=None, nargs="+", help="Alternative to --pagenos with space-separated numbers; supercedes --pagenos where it is used.")
    P.add_argument("-m", "--maxpages", type=int, default=0, help = "Maximum pages to parse")
    P.add_argument("-P", "--password", type=str, default="", help = "Decryption password for PDF")
    P.add_argument("-o", "--outfile", type=str, default="-", help="Output file (default/'-' is stdout)")
    P.add_argument("-t", "--output_type", type=str, default="text", help = "Output type: text|html|xml|tag (default is text)")
    P.add_argument("-c", "--codec", type=str, default="utf-8", help = "Text encoding")
    P.add_argument("-s", "--scale", type=float, default=1.0, help = "Scale")
    P.add_argument("-A", "--all-texts", default=None, action="store_true", help="LAParams all texts")
    P.add_argument("-V", "--detect-vertical", default=None, action="store_true", help="LAParams detect vertical")
    P.add_argument("-W", "--word-margin", type=float, default=None, help = "LAParams word margin")
    P.add_argument("-M", "--char-margin", type=float, default=None, help = "LAParams char margin")
    P.add_argument("-L", "--line-margin", type=float, default=None, help = "LAParams line margin")
    P.add_argument("-F", "--boxes-flow", type=float, default=None, help = "LAParams boxes flow")
    P.add_argument("-Y", "--layoutmode", default="normal", type=str, help="HTML Layout Mode")
    P.add_argument("-n", "--no-laparams", default=False, action="store_true", help = "Pass None as LAParams")
    P.add_argument("-R", "--rotation", default=0, type=int, help = "Rotation")
    P.add_argument("-O", "--output-dir", default=None, help="Output directory for images")
    P.add_argument("-C", "--disable-caching", default=False, action="store_true", help="Disable caching")
    P.add_argument("-S", "--strip-control", default=False, action="store_true", help="Strip control in XML mode")
    A = P.parse_args(args=args)

    if A.no_laparams:
        laparams = None
    else:
        laparams = LAParams()
        for param in ("all_texts", "detect_vertical", "word_margin", "char_margin", "line_margin", "boxes_flow"):
            param_arg = getattr(A, param, None)
            if param_arg is not None:
                setattr(laparams, param, param_arg)

    if A.page_numbers:
        A.page_numbers = set([x-1 for x in A.page_numbers])
    if A.pagenos:
        A.page_numbers = set([int(x)-1 for x in A.pagenos.split(",")])
        
    imagewriter = None
    if A.output_dir:
        imagewriter = ImageWriter(A.output_dir)

    if six.PY2 and sys.stdin.encoding:
        A.password = A.password.decode(sys.stdin.encoding)

    if A.output_type == "text" and A.outfile != "-":
        for override, alttype in (  (".htm",  "html"),
                                    (".html", "html"),
                                    (".xml",  "xml" ),
                                    (".tag",  "tag" ) ):
            if A.outfile.endswith(override):
                A.output_type = alttype

    if A.outfile == "-":
        outfp = sys.stdout
        if outfp.encoding is not None:
            # Why ignore outfp.encoding? :-/ stupid cathal?
            A.codec = 'utf-8'
    else:
        outfp = open(A.outfile, "wb")

    ## Test Code
    outfp = extract_text(**vars(A))
    outfp.close()
    return None

def main_old(argv):
    import getopt
    def usage():
        print ('usage: %s [-d] [-p pagenos] [-m maxpages] [-P password] [-o output]'
               ' [-C] [-n] [-A] [-V] [-M char_margin] [-L line_margin] [-W word_margin]'
               ' [-F boxes_flow] [-Y layout_mode] [-O output_dir] [-R rotation] [-S]'
               ' [-t text|html|xml|tag] [-c codec] [-s scale]'
               ' file ...' % argv[0])
        return 100
    try:
        (opts, args) = getopt.getopt(argv[1:], 'dp:m:P:o:CnAVM:L:W:F:Y:O:R:St:c:s:')
    except getopt.GetoptError:
        return usage()
    if not args: return usage()
    # input option
    password = ''
    pagenos = set()
    maxpages = 0
    # output option
    outfile = None
    outtype = None
    imagewriter = None
    rotation = 0
    stripcontrol = False
    layoutmode = 'normal'
    codec = 'utf-8'
    pageno = 1
    scale = 1
    caching = True
    showpageno = True
    laparams = LAParams()
    for (k, v) in opts:
        if k == '-d': logging.getLogger().setLevel(logging.DEBUG)
        elif k == '-p': pagenos.update( int(x)-1 for x in v.split(',') )
        elif k == '-m': maxpages = int(v)
        elif k == '-P': password = v
        elif k == '-o': outfile = v
        elif k == '-C': caching = False
        elif k == '-n': laparams = None
        elif k == '-A': laparams.all_texts = True
        elif k == '-V': laparams.detect_vertical = True
        elif k == '-M': laparams.char_margin = float(v)
        elif k == '-L': laparams.line_margin = float(v)
        elif k == '-W': laparams.word_margin = float(v)
        elif k == '-F': laparams.boxes_flow = float(v)
        elif k == '-Y': layoutmode = v
        elif k == '-O': imagewriter = ImageWriter(v)
        elif k == '-R': rotation = int(v)
        elif k == '-S': stripcontrol = True
        elif k == '-t': outtype = v
        elif k == '-c': codec = v
        elif k == '-s': scale = float(v)
    #

    if six.PY2 and sys.stdin.encoding:
        password = password.decode(sys.stdin.encoding)

    rsrcmgr = PDFResourceManager(caching=caching)
    if not outtype:
        outtype = 'text'
        if outfile:
            if outfile.endswith('.htm') or outfile.endswith('.html'):
                outtype = 'html'
            elif outfile.endswith('.xml'):
                outtype = 'xml'
            elif outfile.endswith('.tag'):
                outtype = 'tag'
    if outfile:
        outfp = open(outfile, 'wb')
    else:
        outfp = sys.stdout
        if outfp.encoding is not None:
            codec = None
    if outtype == 'text':
        device = TextConverter(rsrcmgr, outfp, codec=codec, laparams=laparams,
                               imagewriter=imagewriter)
    elif outtype == 'xml':
        device = XMLConverter(rsrcmgr, outfp, codec=codec, laparams=laparams,
                              imagewriter=imagewriter,
                              stripcontrol=stripcontrol)
    elif outtype == 'html':
        device = HTMLConverter(rsrcmgr, outfp, codec=codec, scale=scale,
                               layoutmode=layoutmode, laparams=laparams,
                               imagewriter=imagewriter)
    elif outtype == 'tag':
        if six.PY3 and outfp == sys.stdout:
            outfp = sys.stdout.buffer
        device = TagExtractor(rsrcmgr, outfp, codec=codec)
    else:
        return usage()
    for fname in args:
        fp = open(fname, 'rb')
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        for page in PDFPage.get_pages(fp, pagenos,
                                      maxpages=maxpages, password=password,
                                      caching=caching, check_extractable=True):
            page.rotate = (page.rotate+rotation) % 360
            interpreter.process_page(page)
        fp.close()
    device.close()
    outfp.close()
    return

#if __name__ == '__main__': sys.exit(main_old(sys.argv))
if __name__ == '__main__': sys.exit(main())
