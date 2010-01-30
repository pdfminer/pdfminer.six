#!/usr/bin/env python
import sys
from pdfminer.pdfparser import PDFDocument, PDFParser
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter, process_pdf
from pdfminer.pdfdevice import PDFDevice
from pdfminer.converter import XMLConverter, HTMLConverter, TextConverter, TagExtractor
from pdfminer.cmapdb import CMapDB
from pdfminer.layout import LAParams

# main
def main(argv):
    import getopt
    def usage():
        print ('usage: %s [-d] [-p pagenos] [-P password] [-c codec] '
               '[-n] [-D direction] [-M char_margin] [-L line_margin] [-W word_margin] '
               '[-t text|html|xml|tag] [-I imgdir] [-o output] file ...' % argv[0])
        return 100
    try:
        (opts, args) = getopt.getopt(argv[1:], 'dp:P:c:nD:M:L:W:t:I:o:C:D:m:')
    except getopt.GetoptError:
        return usage()
    if not args: return usage()
    # debug option
    debug = 0
    # input option
    password = ''
    pagenos = set()
    maxpages = 0
    # output option
    outfile = None
    outtype = None
    imgdir = None
    codec = 'utf-8'
    pageno = 1
    scale = 1
    showpageno = True
    laparams = LAParams()
    for (k, v) in opts:
        if k == '-d': debug += 1
        elif k == '-P': password = v
        elif k == '-p': pagenos.update( int(x)-1 for x in v.split(',') )
        elif k == '-m': maxpages = int(v)
        elif k == '-t': outtype = v
        elif k == '-c': codec = v
        elif k == '-o': outfile = v
        elif k == '-I': imgdir = v
        elif k == '-s': scale = float(v)
        elif k == '-n': laparams = None
        elif k == '-D': laparams.direction = v
        elif k == '-M': laparams.char_margin = float(v)
        elif k == '-L': laparams.line_margin = float(v)
        elif k == '-W': laparams.word_margin = float(v)
    #
    CMapDB.debug = debug
    PDFResourceManager.debug = debug
    PDFDocument.debug = debug
    PDFParser.debug = debug
    PDFPageInterpreter.debug = debug
    PDFDevice.debug = debug
    #
    rsrc = PDFResourceManager()
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
        outfp = file(outfile, 'w')
    else:
        outfp = sys.stdout
    if outtype == 'text':
        device = TextConverter(rsrc, outfp, codec=codec, laparams=laparams)
    elif outtype == 'xml':
        device = XMLConverter(rsrc, outfp, codec=codec, laparams=laparams, imgdir=imgdir)
    elif outtype == 'html':
        device = HTMLConverter(rsrc, outfp, codec=codec, scale=scale, laparams=laparams, imgdir=imgdir)
    elif outtype == 'tag':
        device = TagExtractor(rsrc, outfp, codec=codec)
    else:
        return usage()
    for fname in args:
        fp = file(fname, 'rb')
        process_pdf(rsrc, device, fp, pagenos, maxpages=maxpages, password=password)
        fp.close()
    device.close()
    outfp.close()
    return

if __name__ == '__main__': sys.exit(main(sys.argv))
