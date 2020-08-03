import hashlib as md5
import logging
import re
import struct

try:
    from Crypto.Cipher import ARC4, AES
    from Crypto.Hash import SHA256
except ImportError:
    AES = SHA256 = None
    from . import arcfour as ARC4
from .psparser import PSEOF, literal_name, LIT, KWD
from . import settings
from .pdftypes import PDFException, uint_value, PDFTypeError, PDFStream, \
    PDFObjectNotFound, decipher_all, int_value, str_value, list_value, \
    dict_value, stream_value
from .pdfparser import PDFSyntaxError, PDFStreamParser
from .utils import choplist, nunpack, decode_text


log = logging.getLogger(__name__)


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


class PDFTextExtractionNotAllowed(PDFEncryptionError):
    pass


# some predefined literals and keywords.
LITERAL_OBJSTM = LIT('ObjStm')
LITERAL_XREF = LIT('XRef')
LITERAL_CATALOG = LIT('Catalog')


class PDFBaseXRef:

    def get_trailer(self):
        raise NotImplementedError

    def get_objids(self):
        return []

    # Must return
    #     (strmid, index, genno)
    #  or (None, pos, genno)
    def get_pos(self, objid):
        raise KeyError(objid)


class PDFXRef(PDFBaseXRef):

    def __init__(self):
        self.offsets = {}
        self.trailer = {}
        return

    def __repr__(self):
        return '<PDFXRef: offsets=%r>' % (self.offsets.keys())

    def load(self, parser):
        while True:
            try:
                (pos, line) = parser.nextline()
                if not line.strip():
                    continue
            except PSEOF:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
            if not line:
                raise PDFNoValidXRef('Premature eof: %r' % parser)
            if line.startswith(b'trailer'):
                parser.seek(pos)
                break
            f = line.strip().split(b' ')
            if len(f) != 2:
                error_msg = 'Trailer not found: {!r}: line={!r}'\
                    .format(parser, line)
                raise PDFNoValidXRef(error_msg)
            try:
                (start, nobjs) = map(int, f)
            except ValueError:
                error_msg = 'Invalid line: {!r}: line={!r}'\
                    .format(parser, line)
                raise PDFNoValidXRef(error_msg)
            for objid in range(start, start+nobjs):
                try:
                    (_, line) = parser.nextline()
                except PSEOF:
                    raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
                f = line.strip().split(b' ')
                if len(f) != 3:
                    error_msg = 'Invalid XRef format: {!r}, line={!r}'\
                        .format(parser, line)
                    raise PDFNoValidXRef(error_msg)
                (pos, genno, use) = f
                if use != b'n':
                    continue
                self.offsets[objid] = (None, int(pos), int(genno))
        log.info('xref objects: %r', self.offsets)
        self.load_trailer(parser)
        return

    def load_trailer(self, parser):
        try:
            (_, kwd) = parser.nexttoken()
            assert kwd is KWD(b'trailer'), str(kwd)
            (_, dic) = parser.nextobject()
        except PSEOF:
            x = parser.pop(1)
            if not x:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted')
            (_, dic) = x[0]
        self.trailer.update(dict_value(dic))
        log.debug('trailer=%r', self.trailer)
        return

    def get_trailer(self):
        return self.trailer

    def get_objids(self):
        return self.offsets.keys()

    def get_pos(self, objid):
        try:
            return self.offsets[objid]
        except KeyError:
            raise


class PDFXRefFallback(PDFXRef):

    def __repr__(self):
        return '<PDFXRefFallback: offsets=%r>' % (self.offsets.keys())

    PDFOBJ_CUE = re.compile(r'^(\d+)\s+(\d+)\s+obj\b')

    def load(self, parser):
        parser.seek(0)
        while 1:
            try:
                (pos, line) = parser.nextline()
            except PSEOF:
                break
            if line.startswith(b'trailer'):
                parser.seek(pos)
                self.load_trailer(parser)
                log.info('trailer: %r', self.trailer)
                break
            line = line.decode('latin-1')  # default pdf encoding
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
            if isinstance(obj, PDFStream) \
                    and obj.get('Type') is LITERAL_OBJSTM:
                stream = stream_value(obj)
                try:
                    n = stream['N']
                except KeyError:
                    if settings.STRICT:
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
                n = min(n, len(objs)//2)
                for index in range(n):
                    objid1 = objs[index*2]
                    self.offsets[objid1] = (objid, index, 0)
        return


class PDFXRefStream(PDFBaseXRef):

    def __init__(self):
        self.data = None
        self.entlen = None
        self.fl1 = self.fl2 = self.fl3 = None
        self.ranges = []
        return

    def __repr__(self):
        return '<PDFXRefStream: ranges=%r>' % (self.ranges)

    def load(self, parser):
        (_, objid) = parser.nexttoken()  # ignored
        (_, genno) = parser.nexttoken()  # ignored
        (_, kwd) = parser.nexttoken()
        (_, stream) = parser.nextobject()
        if not isinstance(stream, PDFStream) \
                or stream['Type'] is not LITERAL_XREF:
            raise PDFNoValidXRef('Invalid PDF stream spec.')
        size = stream['Size']
        index_array = stream.get('Index', (0, size))
        if len(index_array) % 2 != 0:
            raise PDFSyntaxError('Invalid index number')
        self.ranges.extend(choplist(2, index_array))
        (self.fl1, self.fl2, self.fl3) = stream['W']
        self.data = stream.get_data()
        self.entlen = self.fl1+self.fl2+self.fl3
        self.trailer = stream.attrs
        log.info('xref stream: objid=%s, fields=%d,%d,%d',
                 ', '.join(map(repr, self.ranges)),
                 self.fl1, self.fl2, self.fl3)
        return

    def get_trailer(self):
        return self.trailer

    def get_objids(self):
        for (start, nobjs) in self.ranges:
            for i in range(nobjs):
                offset = self.entlen * i
                ent = self.data[offset:offset+self.entlen]
                f1 = nunpack(ent[:self.fl1], 1)
                if f1 == 1 or f1 == 2:
                    yield start+i
        return

    def get_pos(self, objid):
        index = 0
        for (start, nobjs) in self.ranges:
            if start <= objid and objid < start+nobjs:
                index += objid - start
                break
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


class PDFStandardSecurityHandler:

    PASSWORD_PADDING = (b'(\xbfN^Nu\x8aAd\x00NV\xff\xfa\x01\x08'
                        b'..\x00\xb6\xd0h>\x80/\x0c\xa9\xfedSiz')
    supported_revisions = (2, 3)

    def __init__(self, docid, param, password=''):
        self.docid = docid
        self.param = param
        self.password = password
        self.init()
        return

    def init(self):
        self.init_params()
        if self.r not in self.supported_revisions:
            error_msg = 'Unsupported revision: param=%r' % self.param
            raise PDFEncryptionError(error_msg)
        self.init_key()
        return

    def init_params(self):
        self.v = int_value(self.param.get('V', 0))
        self.r = int_value(self.param['R'])
        self.p = uint_value(self.param['P'], 32)
        self.o = str_value(self.param['O'])
        self.u = str_value(self.param['U'])
        self.length = int_value(self.param.get('Length', 40))
        return

    def init_key(self):
        self.key = self.authenticate(self.password)
        if self.key is None:
            raise PDFPasswordIncorrect
        return

    def is_printable(self):
        return bool(self.p & 4)

    def is_modifiable(self):
        return bool(self.p & 8)

    def is_extractable(self):
        return bool(self.p & 16)

    def compute_u(self, key):
        if self.r == 2:
            # Algorithm 3.4
            return ARC4.new(key).encrypt(self.PASSWORD_PADDING)  # 2
        else:
            # Algorithm 3.5
            hash = md5.md5(self.PASSWORD_PADDING)  # 2
            hash.update(self.docid[0])  # 3
            result = ARC4.new(key).encrypt(hash.digest())  # 4
            for i in range(1, 20):  # 5
                k = b''.join(bytes((c ^ i,)) for c in iter(key))
                result = ARC4.new(k).encrypt(result)
            result += result  # 6
            return result

    def compute_encryption_key(self, password):
        # Algorithm 3.2
        password = (password + self.PASSWORD_PADDING)[:32]  # 1
        hash = md5.md5(password)  # 2
        hash.update(self.o)  # 3
        # See https://github.com/pdfminer/pdfminer.six/issues/186
        hash.update(struct.pack('<L', self.p))  # 4
        hash.update(self.docid[0])  # 5
        if self.r >= 4:
            if not self.encrypt_metadata:
                hash.update(b'\xff\xff\xff\xff')
        result = hash.digest()
        n = 5
        if self.r >= 3:
            n = self.length // 8
            for _ in range(50):
                result = md5.md5(result[:n]).digest()
        return result[:n]

    def authenticate(self, password):
        password = password.encode("latin1")
        key = self.authenticate_user_password(password)
        if key is None:
            key = self.authenticate_owner_password(password)
        return key

    def authenticate_user_password(self, password):
        key = self.compute_encryption_key(password)
        if self.verify_encryption_key(key):
            return key
        else:
            return None

    def verify_encryption_key(self, key):
        # Algorithm 3.6
        u = self.compute_u(key)
        if self.r == 2:
            return u == self.u
        return u[:16] == self.u[:16]

    def authenticate_owner_password(self, password):
        # Algorithm 3.7
        password = (password + self.PASSWORD_PADDING)[:32]
        hash = md5.md5(password)
        if self.r >= 3:
            for _ in range(50):
                hash = md5.md5(hash.digest())
        n = 5
        if self.r >= 3:
            n = self.length // 8
        key = hash.digest()[:n]
        if self.r == 2:
            user_password = ARC4.new(key).decrypt(self.o)
        else:
            user_password = self.o
            for i in range(19, -1, -1):
                k = b''.join(bytes((c ^ i,)) for c in iter(key))
                user_password = ARC4.new(k).decrypt(user_password)
        return self.authenticate_user_password(user_password)

    def decrypt(self, objid, genno, data, attrs=None):
        return self.decrypt_rc4(objid, genno, data)

    def decrypt_rc4(self, objid, genno, data):
        key = self.key + struct.pack('<L', objid)[:3] \
              + struct.pack('<L', genno)[:2]
        hash = md5.md5(key)
        key = hash.digest()[:min(len(key), 16)]
        return ARC4.new(key).decrypt(data)


class PDFStandardSecurityHandlerV4(PDFStandardSecurityHandler):

    supported_revisions = (4,)

    def init_params(self):
        super().init_params()
        self.length = 128
        self.cf = dict_value(self.param.get('CF'))
        self.stmf = literal_name(self.param['StmF'])
        self.strf = literal_name(self.param['StrF'])
        self.encrypt_metadata = bool(self.param.get('EncryptMetadata', True))
        if self.stmf != self.strf:
            error_msg = 'Unsupported crypt filter: param=%r' % self.param
            raise PDFEncryptionError(error_msg)
        self.cfm = {}
        for k, v in self.cf.items():
            f = self.get_cfm(literal_name(v['CFM']))
            if f is None:
                error_msg = 'Unknown crypt filter method: param=%r' \
                            % self.param
                raise PDFEncryptionError(error_msg)
            self.cfm[k] = f
        self.cfm['Identity'] = self.decrypt_identity
        if self.strf not in self.cfm:
            error_msg = 'Undefined crypt filter: param=%r' % self.param
            raise PDFEncryptionError(error_msg)
        return

    def get_cfm(self, name):
        if name == 'V2':
            return self.decrypt_rc4
        elif name == 'AESV2':
            return self.decrypt_aes128
        else:
            return None

    def decrypt(self, objid, genno, data, attrs=None, name=None):
        if not self.encrypt_metadata and attrs is not None:
            t = attrs.get('Type')
            if t is not None and literal_name(t) == 'Metadata':
                return data
        if name is None:
            name = self.strf
        return self.cfm[name](objid, genno, data)

    def decrypt_identity(self, objid, genno, data):
        return data

    def decrypt_aes128(self, objid, genno, data):
        key = self.key + struct.pack('<L', objid)[:3] \
              + struct.pack('<L', genno)[:2] + b'sAlT'
        hash = md5.md5(key)
        key = hash.digest()[:min(len(key), 16)]
        return AES.new(key, mode=AES.MODE_CBC, IV=data[:16]).decrypt(data[16:])


class PDFStandardSecurityHandlerV5(PDFStandardSecurityHandlerV4):

    supported_revisions = (5,)

    def init_params(self):
        super().init_params()
        self.length = 256
        self.oe = str_value(self.param['OE'])
        self.ue = str_value(self.param['UE'])
        self.o_hash = self.o[:32]
        self.o_validation_salt = self.o[32:40]
        self.o_key_salt = self.o[40:]
        self.u_hash = self.u[:32]
        self.u_validation_salt = self.u[32:40]
        self.u_key_salt = self.u[40:]
        return

    def get_cfm(self, name):
        if name == 'AESV3':
            return self.decrypt_aes256
        else:
            return None

    def authenticate(self, password):
        password = password.encode('utf-8')[:127]
        hash = SHA256.new(password)
        hash.update(self.o_validation_salt)
        hash.update(self.u)
        if hash.digest() == self.o_hash:
            hash = SHA256.new(password)
            hash.update(self.o_key_salt)
            hash.update(self.u)
            return AES.new(hash.digest(), mode=AES.MODE_CBC, IV=b'\x00' * 16)\
                .decrypt(self.oe)
        hash = SHA256.new(password)
        hash.update(self.u_validation_salt)
        if hash.digest() == self.u_hash:
            hash = SHA256.new(password)
            hash.update(self.u_key_salt)
            return AES.new(hash.digest(), mode=AES.MODE_CBC, IV=b'\x00' * 16)\
                .decrypt(self.ue)
        return None

    def decrypt_aes256(self, objid, genno, data):
        return AES.new(self.key, mode=AES.MODE_CBC, IV=data[:16])\
            .decrypt(data[16:])


class PDFDocument:
    """PDFDocument object represents a PDF document.

    Since a PDF file can be very big, normally it is not loaded at
    once. So PDF document has to cooperate with a PDF parser in order to
    dynamically import the data as processing goes.

    Typical usage:
      doc = PDFDocument(parser, password)
      obj = doc.getobj(objid)

    """

    security_handler_registry = {
        1: PDFStandardSecurityHandler,
        2: PDFStandardSecurityHandler,
    }
    if AES is not None:
        security_handler_registry[4] = PDFStandardSecurityHandlerV4
        if SHA256 is not None:
            security_handler_registry[5] = PDFStandardSecurityHandlerV5

    def __init__(self, parser, password='', caching=True, fallback=True):
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
        self.is_printable = self.is_modifiable = self.is_extractable = True
        # Retrieve the information of each header that was appended
        # (maybe multiple times) at the end of the document.
        try:
            pos = self.find_xref(parser)
            self.read_xref_from(parser, pos, self.xrefs)
        except PDFNoValidXRef:
            pass  # fallback = True
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
                self.encryption = (list_value(trailer['ID']),
                                   dict_value(trailer['Encrypt']))
                self._initialize_password(password)
            if 'Info' in trailer:
                self.info.append(dict_value(trailer['Info']))
            if 'Root' in trailer:
                # Every PDF file must have exactly one /Root dictionary.
                self.catalog = dict_value(trailer['Root'])
                break
        else:
            raise PDFSyntaxError('No /Root object! - Is this really a PDF?')
        if self.catalog.get('Type') is not LITERAL_CATALOG:
            if settings.STRICT:
                raise PDFSyntaxError('Catalog not found!')
        return

    KEYWORD_OBJ = KWD(b'obj')

    # _initialize_password(password=b'')
    #   Perform the initialization with a given password.
    def _initialize_password(self, password=''):
        (docid, param) = self.encryption
        if literal_name(param.get('Filter')) != 'Standard':
            raise PDFEncryptionError('Unknown filter: param=%r' % param)
        v = int_value(param.get('V', 0))
        factory = self.security_handler_registry.get(v)
        if factory is None:
            raise PDFEncryptionError('Unknown algorithm: param=%r' % param)
        handler = factory(docid, param, password)
        self.decipher = handler.decrypt
        self.is_printable = handler.is_printable()
        self.is_modifiable = handler.is_modifiable()
        self.is_extractable = handler.is_extractable()
        self._parser.fallback = False  # need to read streams with exact length
        return

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
            if settings.STRICT:
                raise PDFSyntaxError('Not a stream object: %r' % stream)
        try:
            n = stream['N']
        except KeyError:
            if settings.STRICT:
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

    def _getobj_parse(self, pos, objid):
        self._parser.seek(pos)
        (_, objid1) = self._parser.nexttoken()  # objid
        (_, genno) = self._parser.nexttoken()  # genno
        (_, kwd) = self._parser.nexttoken()
        # hack around malformed pdf files
        # copied from https://github.com/jaepil/pdfminer3k/blob/master/
        # pdfminer/pdfparser.py#L399
        # to solve https://github.com/pdfminer/pdfminer.six/issues/56
        # assert objid1 == objid, str((objid1, objid))
        if objid1 != objid:
            x = []
            while kwd is not self.KEYWORD_OBJ:
                (_, kwd) = self._parser.nexttoken()
                x.append(kwd)
            if x:
                objid1 = x[-2]
        # #### end hack around malformed pdf files
        if objid1 != objid:
            raise PDFSyntaxError('objid mismatch: {!r}={!r}'
                                 .format(objid1, objid))

        if kwd != KWD(b'obj'):
            raise PDFSyntaxError('Invalid object spec: offset=%r' % pos)
        (_, obj) = self._parser.nextobject()
        return obj

    # can raise PDFObjectNotFound
    def getobj(self, objid):
        """Get object from PDF

        :raises PDFException if PDFDocument is not initialized
        :raises PDFObjectNotFound if objid does not exist in PDF
        """
        if not self.xrefs:
            raise PDFException('PDFDocument is not initialized')
        log.debug('getobj: objid=%r', objid)
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
                        if self.decipher:
                            obj = decipher_all(self.decipher, objid, genno,
                                               obj)

                    if isinstance(obj, PDFStream):
                        obj.set_objid(objid, genno)
                    break
                except (PSEOF, PDFSyntaxError):
                    continue
            else:
                raise PDFObjectNotFound(objid)
            log.debug('register: objid=%r: %r', objid, obj)
            if self.caching:
                self._cached_objs[objid] = (obj, genno)
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
                yield from search(entry['First'], level+1)
            if 'Next' in entry:
                yield from search(entry['Next'], level)
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
            log.debug('find_xref: %r', line)
            if line == b'startxref':
                break
            if line:
                prev = line
        else:
            raise PDFNoValidXRef('Unexpected EOF')
        log.info('xref found: pos=%r', prev)
        return int(prev)

    # read xref table
    def read_xref_from(self, parser, start, xrefs):
        """Reads XRefs from the given location."""
        parser.seek(start)
        parser.reset()
        try:
            (pos, token) = parser.nexttoken()
        except PSEOF:
            raise PDFNoValidXRef('Unexpected EOF')
        log.info('read_xref_from: start=%d, token=%r', start, token)
        if isinstance(token, int):
            # XRefStream: PDF-1.5
            parser.seek(pos)
            parser.reset()
            xref = PDFXRefStream()
            xref.load(parser)
        else:
            if token is parser.KEYWORD_XREF:
                parser.nextline()
            xref = PDFXRef()
            xref.load(parser)
        xrefs.append(xref)
        trailer = xref.get_trailer()
        log.info('trailer: %r', trailer)
        if 'XRefStm' in trailer:
            pos = int_value(trailer['XRefStm'])
            self.read_xref_from(parser, pos, xrefs)
        if 'Prev' in trailer:
            # find previous xref
            pos = int_value(trailer['Prev'])
            self.read_xref_from(parser, pos, xrefs)
        return
