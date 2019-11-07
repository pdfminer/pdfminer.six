"""Extract pdf structure in XML format"""
import logging
import os.path
import re
import sys
from argparse import ArgumentParser

import six

from pdfminer.pdfdocument import PDFDocument, PDFNoOutlines
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjectNotFound, PDFValueError
from pdfminer.pdftypes import PDFStream, PDFObjRef, resolve1, stream_value
from pdfminer.psparser import PSKeyword, PSLiteral, LIT
from pdfminer.utils import isnumber

logging.basicConfig()

ESC_PAT = re.compile(r'[\000-\037&<>()"\042\047\134\177-\377]')


def e(s):
    if six.PY3 and isinstance(s, six.binary_type):
        s = str(s, 'latin-1')
    return ESC_PAT.sub(lambda m: '&#%d;' % ord(m.group(0)), s)


def dumpxml(out, obj, codec=None):
    if obj is None:
        out.write('<null />')
        return

    if isinstance(obj, dict):
        out.write('<dict size="%d">\n' % len(obj))
        for (k, v) in six.iteritems(obj):
            out.write('<key>%s</key>\n' % k)
            out.write('<value>')
            dumpxml(out, v)
            out.write('</value>\n')
        out.write('</dict>')
        return

    if isinstance(obj, list):
        out.write('<list size="%d">\n' % len(obj))
        for v in obj:
            dumpxml(out, v)
            out.write('\n')
        out.write('</list>')
        return

    if isinstance(obj, (six.string_types, six.binary_type)):
        out.write('<string size="%d">%s</string>' % (len(obj), e(obj)))
        return

    if isinstance(obj, PDFStream):
        if codec == 'raw':
            out.write(obj.get_rawdata())
        elif codec == 'binary':
            out.write(obj.get_data())
        else:
            out.write('<stream>\n<props>\n')
            dumpxml(out, obj.attrs)
            out.write('\n</props>\n')
            if codec == 'text':
                data = obj.get_data()
                out.write('<data size="%d">%s</data>\n' % (len(data), e(data)))
            out.write('</stream>')
        return

    if isinstance(obj, PDFObjRef):
        out.write('<ref id="%d" />' % obj.objid)
        return

    if isinstance(obj, PSKeyword):
        out.write('<keyword>%s</keyword>' % obj.name)
        return

    if isinstance(obj, PSLiteral):
        out.write('<literal>%s</literal>' % obj.name)
        return

    if isnumber(obj):
        out.write('<number>%s</number>' % obj)
        return

    raise TypeError(obj)


def dumptrailers(out, doc):
    for xref in doc.xrefs:
        out.write('<trailer>\n')
        dumpxml(out, xref.trailer)
        out.write('\n</trailer>\n\n')
    return


def dumpallobjs(out, doc, codec=None):
    visited = set()
    out.write('<pdf>')
    for xref in doc.xrefs:
        for objid in xref.get_objids():
            if objid in visited: continue
            visited.add(objid)
            try:
                obj = doc.getobj(objid)
                if obj is None: continue
                out.write('<object id="%d">\n' % objid)
                dumpxml(out, obj, codec=codec)
                out.write('\n</object>\n\n')
            except PDFObjectNotFound as e:
                print('not found: %r' % e)
    dumptrailers(out, doc)
    out.write('</pdf>')
    return


def dumpoutline(outfp, fname, objids, pagenos, password='',
                dumpall=False, codec=None, extractdir=None):
    fp = open(fname, 'rb')
    parser = PDFParser(fp)
    doc = PDFDocument(parser, password)
    pages = dict((page.pageid, pageno) for (pageno, page)
                 in enumerate(PDFPage.create_pages(doc), 1))

    def resolve_dest(dest):
        if isinstance(dest, str):
            dest = resolve1(doc.get_dest(dest))
        elif isinstance(dest, PSLiteral):
            dest = resolve1(doc.get_dest(dest.name))
        if isinstance(dest, dict):
            dest = dest['D']
        if isinstance(dest, PDFObjRef):
            dest = dest.resolve()
        return dest

    try:
        outlines = doc.get_outlines()
        outfp.write('<outlines>\n')
        for (level, title, dest, a, se) in outlines:
            pageno = None
            if dest:
                dest = resolve_dest(dest)
                pageno = pages[dest[0].objid]
            elif a:
                action = a
                if isinstance(action, dict):
                    subtype = action.get('S')
                    if subtype and repr(subtype) == '/\'GoTo\'' and action.get(
                            'D'):
                        dest = resolve_dest(action['D'])
                        pageno = pages[dest[0].objid]
            s = e(title).encode('utf-8', 'xmlcharrefreplace')
            outfp.write('<outline level="%r" title="%s">\n' % (level, s))
            if dest is not None:
                outfp.write('<dest>')
                dumpxml(outfp, dest)
                outfp.write('</dest>\n')
            if pageno is not None:
                outfp.write('<pageno>%r</pageno>\n' % pageno)
            outfp.write('</outline>\n')
        outfp.write('</outlines>\n')
    except PDFNoOutlines:
        pass
    parser.close()
    fp.close()
    return


LITERAL_FILESPEC = LIT('Filespec')
LITERAL_EMBEDDEDFILE = LIT('EmbeddedFile')


def extractembedded(outfp, fname, objids, pagenos, password='',
                    dumpall=False, codec=None, extractdir=None):
    def extract1(obj):
        filename = os.path.basename(obj['UF'] or obj['F'])
        fileref = obj['EF']['F']
        fileobj = doc.getobj(fileref.objid)
        if not isinstance(fileobj, PDFStream):
            raise PDFValueError(
                'unable to process PDF: reference for %r is not a PDFStream' %
                (filename))
        if fileobj.get('Type') is not LITERAL_EMBEDDEDFILE:
            raise PDFValueError(
                'unable to process PDF: reference for %r is not an EmbeddedFile' %
                (filename))
        path = os.path.join(extractdir, filename)
        if os.path.exists(path):
            raise IOError('file exists: %r' % path)
        print('extracting: %r' % path)
        out = open(path, 'wb')
        out.write(fileobj.get_data())
        out.close()
        return

    fp = open(fname, 'rb')
    parser = PDFParser(fp)
    doc = PDFDocument(parser, password)
    for xref in doc.xrefs:
        for objid in xref.get_objids():
            obj = doc.getobj(objid)
            if isinstance(obj, dict) and obj.get('Type') is LITERAL_FILESPEC:
                extract1(obj)
    fp.close()
    return


def dumppdf(outfp, fname, objids, pagenos, password='',
            dumpall=False, codec=None, extractdir=None):
    fp = open(fname, 'rb')
    parser = PDFParser(fp)
    doc = PDFDocument(parser, password)
    if objids:
        for objid in objids:
            obj = doc.getobj(objid)
            dumpxml(outfp, obj, codec=codec)
    if pagenos:
        for (pageno, page) in enumerate(PDFPage.create_pages(doc)):
            if pageno in pagenos:
                if codec:
                    for obj in page.contents:
                        obj = stream_value(obj)
                        dumpxml(outfp, obj, codec=codec)
                else:
                    dumpxml(outfp, page.attrs)
    if dumpall:
        dumpallobjs(outfp, doc, codec=codec)
    if (not objids) and (not pagenos) and (not dumpall):
        dumptrailers(outfp, doc)
    fp.close()
    if codec not in ('raw', 'binary'):
        outfp.write('\n')
    return


def create_parser():
    parser = ArgumentParser(description=__doc__, add_help=True)
    parser.add_argument('files', type=str, default=None, nargs='+',
                        help='One or more paths to PDF files.')

    parser.add_argument(
        '--debug', '-d', default=False, action='store_true',
        help='Use debug logging level.')
    procedure_parser = parser.add_mutually_exclusive_group()
    procedure_parser.add_argument(
        '--extract-toc', '-T', default=False, action='store_true',
        help='Extract structure of outline')
    procedure_parser.add_argument(
        '--extract-embedded', '-E', type=str,
        help='Extract embedded files')

    parse_params = parser.add_argument_group(
        'Parser', description='Used during PDF parsing')
    parse_params.add_argument(
        '--page-numbers', type=int, default=None, nargs='+',
        help='A space-seperated list of page numbers to parse.')
    parse_params.add_argument(
        '--pagenos', '-p', type=str,
        help='A comma-separated list of page numbers to parse. Included for '
             'legacy applications, use --page-numbers for more idiomatic '
             'argument entry.')
    parse_params.add_argument(
        '--objects', '-i', type=str,
        help='Comma separated list of object numbers to extract')
    parse_params.add_argument(
        '--all', '-a', default=False, action='store_true',
        help='If the structure of all objects should be extracted')
    parse_params.add_argument(
        '--password', '-P', type=str, default='',
        help='The password to use for decrypting PDF file.')

    output_params = parser.add_argument_group(
        'Output', description='Used during output generation.')
    output_params.add_argument(
        '--outfile', '-o', type=str, default='-',
        help='Path to file where output is written. Or "-" (default) to '
             'write to stdout.')
    codec_parser = output_params.add_mutually_exclusive_group()
    codec_parser.add_argument(
        '--raw-stream', '-r', default=False, action='store_true',
        help='Write stream objects without encoding')
    codec_parser.add_argument(
        '--binary-stream', '-b', default=False, action='store_true',
        help='Write stream objects with binary encoding')
    codec_parser.add_argument(
        '--text-stream', '-t', default=False, action='store_true',
        help='Write stream objects as plain text')

    return parser


def main(argv=None):
    parser = create_parser()
    args = parser.parse_args(args=argv)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.outfile == '-':
        outfp = sys.stdout
    else:
        outfp = open(args.outfile, 'w')

    if args.objects:
        objids = [int(x) for x in args.objects.split(',')]
    else:
        objids = []

    if args.page_numbers:
        pagenos = {x - 1 for x in args.page_numbers}
    elif args.pagenos:
        pagenos = {int(x) - 1 for x in args.pagenos.split(',')}
    else:
        pagenos = set()

    password = args.password
    if six.PY2 and sys.stdin.encoding:
        password = password.decode(sys.stdin.encoding)

    if args.raw_stream:
        codec = 'raw'
    elif args.binary_stream:
        codec = 'binary'
    elif args.text_stream:
        codec = 'text'
    else:
        codec = None

    if args.extract_toc:
        extractdir = None
        proc = dumpoutline
    elif args.extract_embedded:
        extractdir = args.extract_embedded
        proc = extractembedded
    else:
        extractdir = None
        proc = dumppdf

    for fname in args.files:
        proc(outfp, fname, objids, pagenos, password=password,
             dumpall=args.all, codec=codec, extractdir=extractdir)
    outfp.close()


if __name__ == '__main__':
    sys.exit(main())
