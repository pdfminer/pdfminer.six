#!/usr/bin/env python
import zlib
from .lzw import lzwdecode
from .ascii85 import ascii85decode
from .ascii85 import asciihexdecode
from .runlength import rldecode
from .ccitt import ccittfaxdecode
from .psparser import PSException
from .psparser import PSObject
from .psparser import LIT
from .psparser import STRICT
from .utils import apply_png_predictor
from .utils import isnumber


LITERAL_CRYPT = LIT('Crypt')

# Abbreviation of Filter names in PDF 4.8.6. "Inline Images"
LITERALS_FLATE_DECODE = (LIT('FlateDecode'), LIT('Fl'))
LITERALS_LZW_DECODE = (LIT('LZWDecode'), LIT('LZW'))
LITERALS_ASCII85_DECODE = (LIT('ASCII85Decode'), LIT('A85'))
LITERALS_ASCIIHEX_DECODE = (LIT('ASCIIHexDecode'), LIT('AHx'))
LITERALS_RUNLENGTH_DECODE = (LIT('RunLengthDecode'), LIT('RL'))
LITERALS_CCITTFAX_DECODE = (LIT('CCITTFaxDecode'), LIT('CCF'))
LITERALS_DCT_DECODE = (LIT('DCTDecode'), LIT('DCT'))


##  PDF Objects
##
class PDFObject(PSObject):
    pass

class PDFException(PSException):
    pass

class PDFTypeError(PDFException):
    pass

class PDFValueError(PDFException):
    pass

class PDFObjectNotFound(PDFException):
    pass

class PDFNotImplementedError(PDFException):
    pass


##  PDFObjRef
##
class PDFObjRef(PDFObject):

    def __init__(self, doc, objid, _):
        if objid == 0:
            if STRICT:
                raise PDFValueError('PDF object id cannot be 0.')
        self.doc = doc
        self.objid = objid
        #self.genno = genno  # Never used.
        return

    def __repr__(self):
        return '<PDFObjRef:%d>' % (self.objid)

    def resolve(self, default=None):
        try:
            return self.doc.getobj(self.objid)
        except PDFObjectNotFound:
            return default


# resolve
def resolve1(x, default=None):
    """Resolves an object.

    If this is an array or dictionary, it may still contains
    some indirect objects inside.
    """
    while isinstance(x, PDFObjRef):
        x = x.resolve(default=default)
    return x


def resolve_all(x, default=None):
    """Recursively resolves the given object and all the internals.

    Make sure there is no indirect reference within the nested object.
    This procedure might be slow.
    """
    while isinstance(x, PDFObjRef):
        x = x.resolve(default=default)
    if isinstance(x, list):
        x = [resolve_all(v, default=default) for v in x]
    elif isinstance(x, dict):
        for (k, v) in x.iteritems():
            x[k] = resolve_all(v, default=default)
    return x


def decipher_all(decipher, objid, genno, x):
    """Recursively deciphers the given object.
    """
    if isinstance(x, str):
        return decipher(objid, genno, x)
    if isinstance(x, list):
        x = [decipher_all(decipher, objid, genno, v) for v in x]
    elif isinstance(x, dict):
        for (k, v) in x.iteritems():
            x[k] = decipher_all(decipher, objid, genno, v)
    return x


# Type checking
def int_value(x):
    x = resolve1(x)
    if not isinstance(x, int):
        if STRICT:
            raise PDFTypeError('Integer required: %r' % x)
        return 0
    return x


def float_value(x):
    x = resolve1(x)
    if not isinstance(x, float):
        if STRICT:
            raise PDFTypeError('Float required: %r' % x)
        return 0.0
    return x


def num_value(x):
    x = resolve1(x)
    if not isnumber(x):
        if STRICT:
            raise PDFTypeError('Int or Float required: %r' % x)
        return 0
    return x


def str_value(x):
    x = resolve1(x)
    if not isinstance(x, str):
        if STRICT:
            raise PDFTypeError('String required: %r' % x)
        return ''
    return x


def list_value(x):
    x = resolve1(x)
    if not isinstance(x, (list, tuple)):
        if STRICT:
            raise PDFTypeError('List required: %r' % x)
        return []
    return x


def dict_value(x):
    x = resolve1(x)
    if not isinstance(x, dict):
        if STRICT:
            raise PDFTypeError('Dict required: %r' % x)
        return {}
    return x


def stream_value(x):
    x = resolve1(x)
    if not isinstance(x, PDFStream):
        if STRICT:
            raise PDFTypeError('PDFStream required: %r' % x)
        return PDFStream({}, '')
    return x


##  PDFStream type
##
class PDFStream(PDFObject):

    def __init__(self, attrs, rawdata, decipher=None):
        assert isinstance(attrs, dict)
        self.attrs = attrs
        self.rawdata = rawdata
        self.decipher = decipher
        self.data = None
        self.objid = None
        self.genno = None
        return

    def set_objid(self, objid, genno):
        self.objid = objid
        self.genno = genno
        return

    def __repr__(self):
        if self.data is None:
            assert self.rawdata is not None
            return '<PDFStream(%r): raw=%d, %r>' % (self.objid, len(self.rawdata), self.attrs)
        else:
            assert self.data is not None
            return '<PDFStream(%r): len=%d, %r>' % (self.objid, len(self.data), self.attrs)

    def __contains__(self, name):
        return name in self.attrs

    def __getitem__(self, name):
        return self.attrs[name]

    def get(self, name, default=None):
        return self.attrs.get(name, default)

    def get_any(self, names, default=None):
        for name in names:
            if name in self.attrs:
                return self.attrs[name]
        return default

    def get_filters(self):
        filters = self.get_any(('F', 'Filter'))
        params = self.get_any(('DP', 'DecodeParms', 'FDecodeParms'), {})
        if not filters:
            return []
        if not isinstance(filters, list):
            filters = [filters]
        if not isinstance(params, list):
            # Make sure the parameters list is the same as filters.
            params = [params]*len(filters)
        if STRICT and len(params) != len(filters):
            raise PDFException("Parameters len filter mismatch")
        return zip(filters, params)

    def decode(self):
        assert self.data is None and self.rawdata is not None
        data = self.rawdata
        if self.decipher:
            # Handle encryption
            data = self.decipher(self.objid, self.genno, data, self.attrs)
        filters = self.get_filters()
        if not filters:
            self.data = data
            self.rawdata = None
            return
        for (f,params) in filters:
            if f in LITERALS_FLATE_DECODE:
                # will get errors if the document is encrypted.
                try:
                    data = zlib.decompress(data)
                except zlib.error as e:
                    if STRICT:
                        raise PDFException('Invalid zlib bytes: %r, %r' % (e, data))
                    data = b''
            elif f in LITERALS_LZW_DECODE:
                data = lzwdecode(data)
            elif f in LITERALS_ASCII85_DECODE:
                data = ascii85decode(data)
            elif f in LITERALS_ASCIIHEX_DECODE:
                data = asciihexdecode(data)
            elif f in LITERALS_RUNLENGTH_DECODE:
                data = rldecode(data)
            elif f in LITERALS_CCITTFAX_DECODE:
                data = ccittfaxdecode(data, params)
            elif f in LITERALS_DCT_DECODE:
                # This is probably a JPG stream - it does not need to be decoded twice.
                # Just return the stream to the user.
                pass
            elif f == LITERAL_CRYPT:
                # not yet..
                raise PDFNotImplementedError('/Crypt filter is unsupported')
            else:
                raise PDFNotImplementedError('Unsupported filter: %r' % f)
            # apply predictors
            if 'Predictor' in params:
                pred = int_value(params['Predictor'])
                if pred == 1:
                    # no predictor
                    pass
                elif 10 <= pred:
                    # PNG predictor
                    colors = int_value(params.get('Colors', 1))
                    columns = int_value(params.get('Columns', 1))
                    bitspercomponent = int_value(params.get('BitsPerComponent', 8))
                    data = apply_png_predictor(pred, colors, columns, bitspercomponent, data)
                else:
                    raise PDFNotImplementedError('Unsupported predictor: %r' % pred)
        self.data = data
        self.rawdata = None
        return

    def get_data(self):
        if self.data is None:
            self.decode()
        return self.data

    def get_rawdata(self):
        return self.rawdata
