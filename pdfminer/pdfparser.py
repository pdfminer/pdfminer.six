#!/usr/bin/env python
import sys
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from psparser import PSStackParser
from psparser import PSSyntaxError, PSEOF
from psparser import KWD, STRICT
from pdftypes import PDFException
from pdftypes import PDFStream, PDFObjRef
from pdftypes import int_value
from pdftypes import dict_value


##  Exceptions
##
class PDFSyntaxError(PDFException):
    pass


##  PDFParser
##
class PDFParser(PSStackParser):

    """
    PDFParser fetch PDF objects from a file stream.
    It can handle indirect references by referring to
    a PDF document set by set_document method.
    It also reads XRefs at the end of every PDF file.

    Typical usage:
      parser = PDFParser(fp)
      parser.read_xref()
      parser.read_xref(fallback=True) # optional
      parser.set_document(doc)
      parser.seek(offset)
      parser.nextobject()

    """

    def __init__(self, fp):
        PSStackParser.__init__(self, fp)
        self.doc = None
        self.fallback = False
        return

    def set_document(self, doc):
        """Associates the parser with a PDFDocument object."""
        self.doc = doc
        return

    KEYWORD_R = KWD('R')
    KEYWORD_NULL = KWD('null')
    KEYWORD_ENDOBJ = KWD('endobj')
    KEYWORD_STREAM = KWD('stream')
    KEYWORD_XREF = KWD('xref')
    KEYWORD_STARTXREF = KWD('startxref')

    def do_keyword(self, pos, token):
        """Handles PDF-related keywords."""

        if token in (self.KEYWORD_XREF, self.KEYWORD_STARTXREF):
            self.add_results(*self.pop(1))

        elif token is self.KEYWORD_ENDOBJ:
            self.add_results(*self.pop(4))

        elif token is self.KEYWORD_NULL:
            # null object
            self.push((pos, None))

        elif token is self.KEYWORD_R:
            # reference to indirect object
            try:
                ((_, objid), (_, genno)) = self.pop(2)
                (objid, genno) = (int(objid), int(genno))
                obj = PDFObjRef(self.doc, objid, genno)
                self.push((pos, obj))
            except PSSyntaxError:
                pass

        elif token is self.KEYWORD_STREAM:
            # stream object
            ((_, dic),) = self.pop(1)
            dic = dict_value(dic)
            objlen = 0
            if not self.fallback:
                try:
                    objlen = int_value(dic['Length'])
                except KeyError:
                    if STRICT:
                        raise PDFSyntaxError('/Length is undefined: %r' % dic)
            self.seek(pos)
            try:
                (_, line) = self.nextline()  # 'stream'
            except PSEOF:
                if STRICT:
                    raise PDFSyntaxError('Unexpected EOF')
                return
            pos += len(line)
            self.fp.seek(pos)
            data = self.fp.read(objlen)
            self.seek(pos+objlen)
            while 1:
                try:
                    (linepos, line) = self.nextline()
                except PSEOF:
                    if STRICT:
                        raise PDFSyntaxError('Unexpected EOF')
                    break
                if 'endstream' in line:
                    i = line.index('endstream')
                    objlen += i
                    data += line[:i]
                    break
                objlen += len(line)
                data += line
            self.seek(pos+objlen)
            # XXX limit objlen not to exceed object boundary
            if 2 <= self.debug:
                print >>sys.stderr, 'Stream: pos=%d, objlen=%d, dic=%r, data=%r...' % \
                                    (pos, objlen, dic, data[:10])
            obj = PDFStream(dic, data, self.doc.decipher)
            self.push((pos, obj))

        else:
            # others
            self.push((pos, token))

        return


##  PDFStreamParser
##
class PDFStreamParser(PDFParser):

    """
    PDFStreamParser is used to parse PDF content streams
    that is contained in each page and has instructions
    for rendering the page. A reference to a PDF document is
    needed because a PDF content stream can also have
    indirect references to other objects in the same document.
    """

    def __init__(self, data):
        PDFParser.__init__(self, StringIO(data))
        return

    def flush(self):
        self.add_results(*self.popall())
        return

    def do_keyword(self, pos, token):
        if token is self.KEYWORD_R:
            # reference to indirect object
            try:
                ((_, objid), (_, genno)) = self.pop(2)
                (objid, genno) = (int(objid), int(genno))
                obj = PDFObjRef(self.doc, objid, genno)
                self.push((pos, obj))
            except PSSyntaxError:
                pass
            return
        # others
        self.push((pos, token))
        return
