#!/usr/bin/env python
#
# dumppdf.py - dump pdf contents in XML format.
#
#  usage: dumppdf.py [options] [files ...]
#  options:
#    -i objid : object id
#
import sys, re
from pdfminer.psparser import PSKeyword, PSLiteral
from pdfminer.pdfparser import PDFDocument, PDFParser
from pdfminer.pdftypes import PDFStream, PDFObjRef, resolve1, stream_value


ESC_PAT = re.compile(r'[\000-\037&<>()\042\047\134\177-\377]')
def esc(s):
    return ESC_PAT.sub(lambda m:'&#%d;' % ord(m.group(0)), s)


# dumpxml
def dumpxml(out, obj, codec=None):
    if isinstance(obj, dict):
        out.write('<dict size="%d">\n' % len(obj))
        for (k,v) in obj.iteritems():
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

    if isinstance(obj, str):
        out.write('<string size="%d">%s</string>' % (len(obj), esc(obj)))
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
                out.write('<data size="%d">%s</data>\n' % (len(data), esc(data)))
            out.write('</stream>')
        return

    if isinstance(obj, PDFObjRef):
        out.write('<ref id="%d"/>' % obj.objid)
        return

    if isinstance(obj, PSKeyword):
        out.write('<keyword>%s</keyword>' % obj.name)
        return

    if isinstance(obj, PSLiteral):
        out.write('<literal>%s</literal>' % obj.name)
        return

    if isinstance(obj, int) or isinstance(obj, float):
        out.write('<number>%s</number>' % obj)
        return

    raise TypeError(obj)

# dumptrailers
def dumptrailers(out, doc):
    for xref in doc.xrefs:
        out.write('<trailer>\n')
        dumpxml(out, xref.trailer)
        out.write('\n</trailer>\n\n')
    return

# dumpallobjs
def dumpallobjs(out, doc, codec=None):
    out.write('<pdf>')
    for xref in doc.xrefs:
        for objid in xref.objids():
            try:
                obj = doc.getobj(objid)
                if obj is None: continue
                out.write('<object id="%d">\n' % objid)
                dumpxml(out, obj, codec=codec)
                out.write('\n</object>\n\n')
            except:
                raise
    dumptrailers(out, doc)
    out.write('</pdf>')
    return

# dumpoutline
def dumpoutline(outfp, fname, objids, pagenos, password='',
                dumpall=False, codec=None):
    doc = PDFDocument()
    fp = file(fname, 'rb')
    parser = PDFParser(fp)
    parser.set_document(doc)
    doc.set_parser(parser)
    doc.initialize(password)
    pages = dict( (page.pageid, pageno) for (pageno,page) in enumerate(doc.get_pages()) )
    for (level,title,dest,a,se) in doc.get_outlines():
        pageno = None
        if dest:
            dest = resolve1( doc.lookup_name('Dests', dest) )
            if isinstance(dest, dict):
                dest = dest['D']
            pageno = pages[dest[0].objid]
        outfp.write(repr((level,title,dest,pageno))+'\n')
    parser.close()
    fp.close()
    return

# dumppdf
def dumppdf(outfp, fname, objids, pagenos, password='',
            dumpall=False, codec=None):
    doc = PDFDocument()
    fp = file(fname, 'rb')
    parser = PDFParser(fp)
    parser.set_document(doc)
    doc.set_parser(parser)
    doc.initialize(password)
    if objids:
        for objid in objids:
            obj = doc.getobj(objid)
            dumpxml(outfp, obj, codec=codec)
    if pagenos:
        for (pageno,page) in enumerate(doc.get_pages()):
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
    if codec not in ('raw','binary'):
        outfp.write('\n')
    return


# main
def main(argv):
    import getopt
    def usage():
        print 'usage: %s [-d] [-a] [-p pageid] [-P password] [-r|-b|-t] [-T] [-i objid] file ...' % argv[0]
        return 100
    try:
        (opts, args) = getopt.getopt(argv[1:], 'dap:P:rbtTi:')
    except getopt.GetoptError:
        return usage()
    if not args: return usage()
    debug = 0
    objids = []
    pagenos = set()
    codec = None
    password = ''
    dumpall = False
    proc = dumppdf
    outfp = sys.stdout
    for (k, v) in opts:
        if k == '-d': debug += 1
        elif k == '-i': objids.extend( int(x) for x in v.split(',') )
        elif k == '-p': pagenos.update( int(x)-1 for x in v.split(',') )
        elif k == '-P': password = v
        elif k == '-a': dumpall = True
        elif k == '-r': codec = 'raw'
        elif k == '-b': codec = 'binary'
        elif k == '-t': codec = 'text'
        elif k == '-T': proc = dumpoutline
        elif k == '-o': outfp = file(v, 'wb')
    #
    PDFDocument.debug = debug
    PDFParser.debug = debug
    #
    for fname in args:
        proc(outfp, fname, objids, pagenos, password=password,
             dumpall=dumpall, codec=codec)
    return

if __name__ == '__main__': sys.exit(main(sys.argv))
