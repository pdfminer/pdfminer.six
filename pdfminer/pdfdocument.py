#!/usr/bin/env python
import sys
import re
import struct
try:
    import hashlib as md5
except ImportError:
    import md5
from psparser import PSEOF
from psparser import literal_name
from psparser import LIT, KWD, STRICT
from pdftypes import PDFException, PDFTypeError, PDFNotImplementedError
from pdftypes import PDFObjectNotFound, PDFStream
from pdftypes import decipher_all
from pdftypes import int_value
from pdftypes import str_value, list_value, dict_value, stream_value
from pdfparser import PDFSyntaxError
from pdfparser import PDFStreamParser
from arcfour import Arcfour
from utils import choplist, nunpack
from utils import decode_text


##  Exceptions
##
class PDFNoValidXRef(PDFSyntaxError):
    pass


class PDFNoOutlines(PDFException):
    pass


class PDFDestinationNotFound(PDFException):
    pass


class PDFEncryptionError(PDFException):
    pass


class PDFPasswordIncorrect(PDFEncryptionError):
    pass

# some predefined literals and keywords.
LITERAL_OBJSTM = LIT('ObjStm')
LITERAL_XREF = LIT('XRef')
LITERAL_CATALOG = LIT('Catalog')


##  XRefs
##
class PDFBaseXRef(object):

    def get_trailer(self):
        raise NotImplementedError

    def get_objids(self):
        return []

    # Must return
    #     (strmid, index, genno)
    #  or (None, pos, genno)
    def get_pos(self, objid):
        raise KeyError(objid)


##  PDFXRef
##
class PDFXRef(PDFBaseXRef):

    def __init__(self):
        self.offsets = {}
        self.trailer = {}
        return

    def __repr__(self):
        return '<PDFXRef: offsets=%r>' % (self.offsets.keys())

    def load(self, parser, debug=0):
        while 1:
            try:
                (pos, line) = parser.nextline()
                if not line.strip():
                    continue
            except PSEOF:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
            if not line:
                raise PDFNoValidXRef('Premature eof: %r' % parser)
            if line.startswith('trailer'):
                parser.seek(pos)
                break
            f = line.strip().split(' ')
            if len(f) != 2:
                raise PDFNoValidXRef('Trailer not found: %r: line=%r' % (parser, line))
            try:
                (start, nobjs) = map(long, f)
            except ValueError:
                raise PDFNoValidXRef('Invalid line: %r: line=%r' % (parser, line))
            for objid in xrange(start, start+nobjs):
                try:
                    (_, line) = parser.nextline()
                except PSEOF:
                    raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
                f = line.strip().split(' ')
                if len(f) != 3:
                    raise PDFNoValidXRef('Invalid XRef format: %r, line=%r' % (parser, line))
                (pos, genno, use) = f
                if use != 'n':
                    continue
                self.offsets[objid] = (None, long(pos), int(genno))
        if 1 <= debug:
            print >>sys.stderr, 'xref objects:', self.offsets
        self.load_trailer(parser)
        return

    KEYWORD_TRAILER = KWD('trailer')

    def load_trailer(self, parser):
        try:
            (_, kwd) = parser.nexttoken()
            assert kwd is self.KEYWORD_TRAILER
            (_, dic) = parser.nextobject()
        except PSEOF:
            x = parser.pop(1)
            if not x:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted')
            (_, dic) = x[0]
        self.trailer.update(dict_value(dic))
        return

    def get_trailer(self):
        return self.trailer

    def get_objids(self):
        return self.offsets.iterkeys()

    def get_pos(self, objid):
        try:
            return self.offsets[objid]
        except KeyError:
            raise


##  PDFXRefFallback
##
class PDFXRefFallback(PDFXRef):

    def __repr__(self):
        return '<PDFXRefFallback: offsets=%r>' % (self.offsets.keys())

    PDFOBJ_CUE = re.compile(r'^(\d+)\s+(\d+)\s+obj\b')

    def load(self, parser, debug=0):
        parser.seek(0)
        while 1:
            try:
                (pos, line) = parser.nextline()
            except PSEOF:
                break
            if line.startswith('trailer'):
                parser.seek(pos)
                self.load_trailer(parser)
                if 1 <= debug:
                    print >>sys.stderr, 'trailer: %r' % self.get_trailer()
                break
            m = self.PDFOBJ_CUE.match(line)
            if not m:
                continue
            (objid, genno) = m.groups()
            objid = int(objid)
            genno = int(genno)
            self.offsets[objid] = (None, pos, genno)
            # expand ObjStm.
            parser.seek(pos)
            (_, obj) = parser.nextobject()
            if isinstance(obj, PDFStream) and obj.get('Type') is LITERAL_OBJSTM:
                stream = stream_value(obj)
                try:
                    n = stream['N']
                except KeyError:
                    if STRICT:
                        raise PDFSyntaxError('N is not defined: %r' % stream)
                    n = 0
                parser1 = PDFStreamParser(stream.get_data())
                objs = []
                try:
                    while 1:
                        (_, obj) = parser1.nextobject()
                        objs.append(obj)
                except PSEOF:
                    pass
                for index in xrange(n):
                    objid1 = objs[index*2]
                    self.offsets[objid1] = (objid, index, 0)
        return


##  PDFXRefStream
##
class PDFXRefStream(PDFBaseXRef):

    def __init__(self):
        self.data = None
        self.entlen = None
        self.fl1 = self.fl2 = self.fl3 = None
        self.ranges = []
        return

    def __repr__(self):
        return '<PDFXRefStream: ranges=%r>' % (self.ranges)

    def load(self, parser, debug=0):
        (_, objid) = parser.nexttoken()  # ignored
        (_, genno) = parser.nexttoken()  # ignored
        (_, kwd) = parser.nexttoken()
        (_, stream) = parser.nextobject()
        if not isinstance(stream, PDFStream) or stream['Type'] is not LITERAL_XREF:
            raise PDFNoValidXRef('Invalid PDF stream spec.')
        size = stream['Size']
        index_array = stream.get('Index', (1, size))
        if len(index_array) % 2 != 0:
            raise PDFSyntaxError('Invalid index number')
        self.ranges.extend(choplist(2, index_array))
        (self.fl1, self.fl2, self.fl3) = stream['W']
        self.data = stream.get_data()
        self.entlen = self.fl1+self.fl2+self.fl3
        self.trailer = stream.attrs
        if 1 <= debug:
            print >>sys.stderr, ('xref stream: objid=%s, fields=%d,%d,%d' %
                                 (', '.join(map(repr, self.ranges)),
                                 self.fl1, self.fl2, self.fl3))
        return

    def get_trailer(self):
        return self.trailer

    def get_objids(self):
        for (start, nobjs) in self.ranges:
            for i in xrange(nobjs):
                yield start+i
        return

    def get_pos(self, objid):
        index = 0
        for (start, nobjs) in self.ranges:
            if start <= objid and objid < start+nobjs:
                index += objid - start
            else:
                index += nobjs
        else:
            raise KeyError(objid)
        offset = self.entlen * index
        ent = self.data[offset:offset+self.entlen]
        f1 = nunpack(ent[:self.fl1], 1)
        f2 = nunpack(ent[self.fl1:self.fl1+self.fl2])
        f3 = nunpack(ent[self.fl1+self.fl2:])
        if f1 == 1:
            return (None, f2, f3)
        elif f1 == 2:
            return (f2, f3, 0)
        else:
            # this is a free object
            raise KeyError(objid)


##  PDFDocument
##
class PDFDocument(object):

    """PDFDocument object represents a PDF document.

    Since a PDF file can be very big, normally it is not loaded at
    once. So PDF document has to cooperate with a PDF parser in order to
    dynamically import the data as processing goes.

    Typical usage:
      doc = PDFDocument(parser)
      doc.initialize(password)
      obj = doc.getobj(objid)

    """

    debug = 0

    def __init__(self, parser, caching=True, fallback=True):
        "Set the document to use a given PDFParser object."
        self.caching = caching
        self.xrefs = []
        self.info = []
        self.catalog = None
        self.encryption = None
        self.decipher = None
        self._parser = None
        self._cached_objs = {}
        self._parsed_objs = {}
        self._parser = parser
        self._parser.set_document(self)
        # Retrieve the information of each header that was appended
        # (maybe multiple times) at the end of the document.
        try:
            pos = self.find_xref(parser)
            self.read_xref_from(parser, pos, self.xrefs)
        except PDFNoValidXRef:
            fallback = True
        if fallback:
            parser.fallback = True
            xref = PDFXRefFallback()
            xref.load(parser)
            self.xrefs.append(xref)
        for xref in self.xrefs:
            trailer = xref.get_trailer()
            if not trailer:
                continue
            # If there's an encryption info, remember it.
            if 'Encrypt' in trailer:
                #assert not self.encryption
                self.encryption = (list_value(trailer['ID']),
                                   dict_value(trailer['Encrypt']))
            if 'Info' in trailer:
                self.info.append(dict_value(trailer['Info']))
            if 'Root' in trailer:
                # Every PDF file must have exactly one /Root dictionary.
                self.catalog = dict_value(trailer['Root'])
                break
        else:
            raise PDFSyntaxError('No /Root object! - Is this really a PDF?')
        if self.catalog.get('Type') is not LITERAL_CATALOG:
            if STRICT:
                raise PDFSyntaxError('Catalog not found!')
        return

    # initialize(password='')
    #   Perform the initialization with a given password.
    #   This step is mandatory even if there's no password associated
    #   with the document.
    PASSWORD_PADDING = '(\xbfN^Nu\x8aAd\x00NV\xff\xfa\x01\x08..\x00\xb6\xd0h>\x80/\x0c\xa9\xfedSiz'

    def initialize(self, password=''):
        if not self.encryption:
            self.is_printable = self.is_modifiable = self.is_extractable = True
            return
        (docid, param) = self.encryption
        if literal_name(param.get('Filter')) != 'Standard':
            raise PDFEncryptionError('Unknown filter: param=%r' % param)
        V = int_value(param.get('V', 0))
        if not (V == 1 or V == 2):
            raise PDFEncryptionError('Unknown algorithm: param=%r' % param)
        length = int_value(param.get('Length', 40))  # Key length (bits)
        O = str_value(param['O'])
        R = int_value(param['R'])  # Revision
        if 5 <= R:
            raise PDFEncryptionError('Unknown revision: %r' % R)
        U = str_value(param['U'])
        P = int_value(param['P'])
        self.is_printable = bool(P & 4)
        self.is_modifiable = bool(P & 8)
        self.is_extractable = bool(P & 16)
        # Algorithm 3.2
        password = (password+self.PASSWORD_PADDING)[:32]  # 1
        hash = md5.md5(password)  # 2
        hash.update(O)  # 3
        hash.update(struct.pack('<l', P))  # 4
        hash.update(docid[0])  # 5
        if 4 <= R:
            # 6
            raise PDFNotImplementedError('Revision 4 encryption is currently unsupported')
        if 3 <= R:
            # 8
            for _ in xrange(50):
                hash = md5.md5(hash.digest()[:length/8])
        key = hash.digest()[:length/8]
        if R == 2:
            # Algorithm 3.4
            u1 = Arcfour(key).process(self.PASSWORD_PADDING)
        elif R == 3:
            # Algorithm 3.5
            hash = md5.md5(self.PASSWORD_PADDING)  # 2
            hash.update(docid[0])  # 3
            x = Arcfour(key).process(hash.digest()[:16])  # 4
            for i in xrange(1, 19+1):
                k = ''.join(chr(ord(c) ^ i) for c in key)
                x = Arcfour(k).process(x)
            u1 = x+x  # 32bytes total
        if R == 2:
            is_authenticated = (u1 == U)
        else:
            is_authenticated = (u1[:16] == U[:16])
        if not is_authenticated:
            raise PDFPasswordIncorrect
        self.decrypt_key = key
        self.decipher = self.decrypt_rc4  # XXX may be AES
        return

    def decrypt_rc4(self, objid, genno, data):
        key = self.decrypt_key + struct.pack('<L', objid)[:3]+struct.pack('<L', genno)[:2]
        hash = md5.md5(key)
        key = hash.digest()[:min(len(key), 16)]
        return Arcfour(key).process(data)

    def _getobj_objstm(self, stream, index, objid):
        if stream.objid in self._parsed_objs:
            (objs, n) = self._parsed_objs[stream.objid]
        else:
            (objs, n) = self._get_objects(stream)
            if self.caching:
                self._parsed_objs[stream.objid] = (objs, n)
        i = n*2+index
        try:
            obj = objs[i]
        except IndexError:
            raise PDFSyntaxError('index too big: %r' % index)
        return obj

    def _get_objects(self, stream):
        if stream.get('Type') is not LITERAL_OBJSTM:
            if STRICT:
                raise PDFSyntaxError('Not a stream object: %r' % stream)
        try:
            n = stream['N']
        except KeyError:
            if STRICT:
                raise PDFSyntaxError('N is not defined: %r' % stream)
            n = 0
        parser = PDFStreamParser(stream.get_data())
        parser.set_document(self)
        objs = []
        try:
            while 1:
                (_, obj) = parser.nextobject()
                objs.append(obj)
        except PSEOF:
            pass
        return (objs, n)

    KEYWORD_OBJ = KWD('obj')

    def _getobj_parse(self, pos, objid):
        self._parser.seek(pos)
        (_, objid1) = self._parser.nexttoken()  # objid
        if objid1 != objid:
            raise PDFSyntaxError('objid mismatch: %r=%r' % (objid1, objid))
        (_, genno) = self._parser.nexttoken()  # genno
        (_, kwd) = self._parser.nexttoken()
        if kwd is not self.KEYWORD_OBJ:
            raise PDFSyntaxError('Invalid object spec: offset=%r' % pos)
        (_, obj) = self._parser.nextobject()
        return obj

    # can raise PDFObjectNotFound
    def getobj(self, objid):
        assert objid != 0
        if not self.xrefs:
            raise PDFException('PDFDocument is not initialized')
        if 2 <= self.debug:
            print >>sys.stderr, 'getobj: objid=%r' % (objid)
        if objid in self._cached_objs:
            (obj, genno) = self._cached_objs[objid]
        else:
            for xref in self.xrefs:
                try:
                    (strmid, index, genno) = xref.get_pos(objid)
                except KeyError:
                    continue
                try:
                    if strmid is not None:
                        stream = stream_value(self.getobj(strmid))
                        obj = self._getobj_objstm(stream, index, objid)
                    else:
                        obj = self._getobj_parse(index, objid)
                    if isinstance(obj, PDFStream):
                        obj.set_objid(objid, genno)
                    break
                except (PSEOF, PDFSyntaxError):
                    continue
            else:
                raise PDFObjectNotFound(objid)
            if 2 <= self.debug:
                print >>sys.stderr, 'register: objid=%r: %r' % (objid, obj)
            if self.caching:
                self._cached_objs[objid] = (obj, genno)
        if self.decipher:
            obj = decipher_all(self.decipher, objid, genno, obj)
        return obj

    def get_outlines(self):
        if 'Outlines' not in self.catalog:
            raise PDFNoOutlines

        def search(entry, level):
            entry = dict_value(entry)
            if 'Title' in entry:
                if 'A' in entry or 'Dest' in entry:
                    title = decode_text(str_value(entry['Title']))
                    dest = entry.get('Dest')
                    action = entry.get('A')
                    se = entry.get('SE')
                    yield (level, title, dest, action, se)
            if 'First' in entry and 'Last' in entry:
                for x in search(entry['First'], level+1):
                    yield x
            if 'Next' in entry:
                for x in search(entry['Next'], level):
                    yield x
            return
        return search(self.catalog['Outlines'], 0)

    def lookup_name(self, cat, key):
        try:
            names = dict_value(self.catalog['Names'])
        except (PDFTypeError, KeyError):
            raise KeyError((cat, key))
        # may raise KeyError
        d0 = dict_value(names[cat])

        def lookup(d):
            if 'Limits' in d:
                (k1, k2) = list_value(d['Limits'])
                if key < k1 or k2 < key:
                    return None
            if 'Names' in d:
                objs = list_value(d['Names'])
                names = dict(choplist(2, objs))
                return names[key]
            if 'Kids' in d:
                for c in list_value(d['Kids']):
                    v = lookup(dict_value(c))
                    if v:
                        return v
            raise KeyError((cat, key))
        return lookup(d0)

    def get_dest(self, name):
        try:
            # PDF-1.2 or later
            obj = self.lookup_name('Dests', name)
        except KeyError:
            # PDF-1.1 or prior
            if 'Dests' not in self.catalog:
                raise PDFDestinationNotFound(name)
            d0 = dict_value(self.catalog['Dests'])
            if name not in d0:
                raise PDFDestinationNotFound(name)
            obj = d0[name]
        return obj

    # find_xref
    def find_xref(self, parser):
        """Internal function used to locate the first XRef."""
        # search the last xref table by scanning the file backwards.
        prev = None
        for line in parser.revreadlines():
            line = line.strip()
            if 2 <= self.debug:
                print >>sys.stderr, 'find_xref: %r' % line
            if line == 'startxref':
                break
            if line:
                prev = line
        else:
            raise PDFNoValidXRef('Unexpected EOF')
        if 1 <= self.debug:
            print >>sys.stderr, 'xref found: pos=%r' % prev
        return long(prev)

    # read xref table
    def read_xref_from(self, parser, start, xrefs):
        """Reads XRefs from the given location."""
        parser.seek(start)
        parser.reset()
        try:
            (pos, token) = parser.nexttoken()
        except PSEOF:
            raise PDFNoValidXRef('Unexpected EOF')
        if 2 <= self.debug:
            print >>sys.stderr, 'read_xref_from: start=%d, token=%r' % (start, token)
        if isinstance(token, int):
            # XRefStream: PDF-1.5
            parser.seek(pos)
            parser.reset()
            xref = PDFXRefStream()
            xref.load(parser, debug=self.debug)
        else:
            if token is parser.KEYWORD_XREF:
                parser.nextline()
            xref = PDFXRef()
            xref.load(parser, debug=self.debug)
        xrefs.append(xref)
        trailer = xref.get_trailer()
        if 1 <= self.debug:
            print >>sys.stderr, 'trailer: %r' % trailer
        if 'XRefStm' in trailer:
            pos = int_value(trailer['XRefStm'])
            self.read_xref_from(parser, pos, xrefs)
        if 'Prev' in trailer:
            # find previous xref
            pos = int_value(trailer['Prev'])
            self.read_xref_from(parser, pos, xrefs)
        return
