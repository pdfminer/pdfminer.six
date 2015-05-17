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

# main
def main(argv):
    import argparse
    P = argparse.ArgumentParser(description=__doc__)
    P.add_argument("files", type=str, nargs="+", help="Files to process.")
    P.add_argument("-d", "--debug", default=False, action="store_true", help="Debug output.")
    P.add_argument("-p", "--pagenos", type=str, help="Comma-separated list of page numbers to parse. Included for legacy applications, use -P/--page-numbers for more idiomatic argument entry.")
    P.add_argument("--page-numbers", type=int, nargs="+", help="Alternative to --pagenos with space-separated numbers; supercedes --pagenos where it is used.")
    P.add_argument("-m", "--maxpages", type=int, default=0, help = "Maximum pages to parse")
    P.add_argument("-P", "--password", type=str, default="", help = "Decryption password for PDF")
#    P.add_argument("-o", "--outfile", type=argparse.FileType("w"), default=sys.stdout, help="Output file (default stdout)")
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
    A = P.parse_args()

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
        for override, alttype in (  (".htm", "html"),
                                    (".html", "html"),
                                    (".xml", "xml"),
                                    (".tag", "tag") ):
            if A.outfile.endswith(override):
                A.output_type = alttype

    if A.outfile == "-":
        outfp = sys.stdout
        if outfp.encoding is not None:
            A.codec = 'utf-8'
            #A.codec = outfp.encoding
    else:
        outfp = open(A.outfile, "wb")

    rsrcmgr = PDFResourceManager(caching=not A.disable_caching)

    if A.output_type == 'text':
        device = TextConverter(rsrcmgr, outfp, codec=A.codec, laparams=laparams,
                               imagewriter=imagewriter)
    elif A.output_type == 'xml':
        if six.PY3 and outfp == sys.stdout:
            outfp = sys.stdout.buffer
        device = XMLConverter(rsrcmgr, outfp, codec=A.codec, laparams=laparams,
                              imagewriter=imagewriter,
                              stripcontrol=A.strip_control)
    elif A.output_type == 'html':
        if six.PY3 and outfp == sys.stdout:
            outfp = sys.stdout.buffer
        device = HTMLConverter(rsrcmgr, outfp, codec=A.codec, scale=A.scale,
                               layoutmode=A.layoutmode, laparams=laparams,
                               imagewriter=imagewriter)
    elif A.output_type == 'tag':
        if six.PY3 and outfp == sys.stdout:
            outfp = sys.stdout.buffer
        device = TagExtractor(rsrcmgr, outfp, codec=A.codec)
    else:
        return usage()
    for fname in A.files:
        fp = open(fname, 'rb')
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        for page in PDFPage.get_pages(fp, A.page_numbers,
                                      maxpages=A.maxpages, password=A.password,
                                      caching=not A.disable_caching, check_extractable=True):
            page.rotate = (page.rotate + A.rotation) % 360
            interpreter.process_page(page)
        fp.close()
    device.close()
    outfp.close()
    return

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
if __name__ == '__main__': sys.exit(main(sys.argv))
