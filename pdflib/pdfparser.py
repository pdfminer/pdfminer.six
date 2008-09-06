#!/usr/bin/env python

# pdfparser.py, Yusuke Shinyama
#  ver 0.1, Dec 24 2004-
#  ver 0.2, Dec 24 2007

import sys, re
import md5, struct
stderr = sys.stderr
from utils import choplist, nunpack
from arcfour import Arcfour
from lzw import LZWDecoder
from psparser import PSException, PSSyntaxError, PSTypeError, PSEOF, \
     PSObject, PSLiteral, PSKeyword, PSLiteralTable, PSKeywordTable, \
     literal_name, keyword_name, \
     PSStackParser, STRICT


##  PDF Exceptions
##
class PDFException(PSException): pass
class PDFSyntaxError(PDFException): pass
class PDFNoValidXRef(PDFSyntaxError): pass
class PDFEncryptionError(PDFException): pass
class PDFPasswordIncorrect(PDFEncryptionError): pass
class PDFTypeError(PDFException): pass
class PDFValueError(PDFException): pass
class PDFNotImplementedError(PSException): pass


# some predefined literals and keywords.
LITERAL_OBJSTM = PSLiteralTable.intern('ObjStm')
LITERAL_XREF = PSLiteralTable.intern('XRef')
LITERAL_PAGE = PSLiteralTable.intern('Page')
LITERAL_PAGES = PSLiteralTable.intern('Pages')
LITERAL_CATALOG = PSLiteralTable.intern('Catalog')
LITERAL_CRYPT = PSLiteralTable.intern('Crypt')
LITERALS_FLATE_DECODE = (PSLiteralTable.intern('FlateDecode'),
                         PSLiteralTable.intern('Fl'))
LITERALS_LZW_DECODE = (PSLiteralTable.intern('LZWDecode'),
                       PSLiteralTable.intern('LZW'))
LITERALS_ASCII85_DECODE = (PSLiteralTable.intern('ASCII85Decode'),
                           PSLiteralTable.intern('A85'))
KEYWORD_R = PSKeywordTable.intern('R')
KEYWORD_OBJ = PSKeywordTable.intern('obj')
KEYWORD_ENDOBJ = PSKeywordTable.intern('endobj')
KEYWORD_STREAM = PSKeywordTable.intern('stream')
KEYWORD_XREF = PSKeywordTable.intern('xref')
KEYWORD_TRAILER = PSKeywordTable.intern('trailer')
KEYWORD_STARTXREF = PSKeywordTable.intern('startxref')
PASSWORD_PADDING = '(\xbfN^Nu\x8aAd\x00NV\xff\xfa\x01\x08..\x00\xb6\xd0h>\x80/\x0c\xa9\xfedSiz'

class PDFObject(PSObject): pass


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

  def resolve(self):
    return self.doc.getobj(self.objid)


# resolve
def resolve1(x):
  '''
  Resolve an object. If this is an array or dictionary,
  it may still contains some indirect objects inside.
  '''
  while isinstance(x, PDFObjRef):
    x = x.resolve()
  return x

def resolve_all(x):
  '''
  Recursively resolve X and all the internals.
  Make sure there is no indirect reference within the nested object.
  This procedure might be slow.
  '''
  while isinstance(x, PDFObjRef):
    x = x.resolve()
  if isinstance(x, list):
    x = [ resolve_all(v) for v in x ]
  elif isinstance(x, dict):
    for (k,v) in x.iteritems():
      x[k] = resolve_all(v)
  return x

def decipher_all(decipher, objid, genno, x):
  '''
  Recursively decipher X.
  '''
  if isinstance(x, str):
    return decipher(objid, genno, x)
  if isinstance(x, list):
    x = [ decipher_all(decipher, objid, genno, v) for v in x ]
  elif isinstance(x, dict):
    for (k,v) in x.iteritems():
      x[k] = decipher_all(decipher, objid, genno, v)
  return x

# Type cheking
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
  if not (isinstance(x, int) or isinstance(x, float)):
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
  if not (isinstance(x, list) or isinstance(x, tuple)):
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
  
  def __init__(self, dic, rawdata, decipher=None):
    self.dic = dic
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
    return '<PDFStream(%r): raw=%d, %r>' % (self.objid, len(self.rawdata), self.dic)

  def decode(self):
    assert self.data == None and self.rawdata != None
    data = self.rawdata
    if self.decipher:
      # Handle encryption
      data = self.decipher(self.objid, self.genno, data)
    if 'Filter' not in self.dic:
      self.data = data
      self.rawdata = None
      return
    filters = self.dic['Filter']
    if not isinstance(filters, list):
      filters = [ filters ]
    for f in filters:
      if f in LITERALS_FLATE_DECODE:
        import zlib
        # will get errors if the document is encrypted.
        data = zlib.decompress(data)
      elif f in LITERALS_LZW_DECODE:
        try:
          from cStringIO import StringIO
        except ImportError:
          from StringIO import StringIO
        data = ''.join(LZWDecoder(StringIO(data)).run())
      elif f in LITERALS_ASCII85_DECODE:
        import ascii85
        data = ascii85.ascii85decode(data)
      elif f == LITERAL_CRYPT:
        raise PDFEncryptionError('/Crypt filter is unsupported')
      else:
        raise PDFNotImplementedError('Unsupported filter: %r' % f)
      # apply predictors
      params = self.dic.get('DecodeParms', {})
      if 'Predictor' in params:
        pred = int_value(params['Predictor'])
        if pred:
          if pred != 12:
            raise PDFNotImplementedError('Unsupported predictor: %r' % pred)
          if 'Columns' not in params:
            raise PDFValueError('Columns undefined for predictor=12')
          columns = int_value(params['Columns'])
          buf = ''
          ent0 = '\x00' * columns
          for i in xrange(0, len(data), columns+1):
            pred = data[i]
            ent1 = data[i+1:i+1+columns]
            if pred == '\x02':
              ent1 = ''.join( chr((ord(a)+ord(b)) & 255) for (a,b) in zip(ent0,ent1) )
            buf += ent1
            ent0 = ent1
          data = buf
    self.data = data
    self.rawdata = None
    return

  def get_data(self):
    if self.data == None:
      self.decode()
    return self.data

  def get_rawdata(self):
    return self.rawdata
  

##  PDFPage
##
class PDFPage(object):
  
  def __init__(self, doc, pageid, attrs):
    self.doc = doc
    self.pageid = pageid
    self.attrs = dict_value(attrs)
    self.lastmod = self.attrs.get('LastModified')
    self.resources = resolve1(self.attrs['Resources'])
    self.mediabox = resolve1(self.attrs['MediaBox'])
    if 'CropBox' in self.attrs:
      self.cropbox = resolve1(self.attrs['CropBox'])
    else:
      self.cropbox = self.mediabox
    self.rotate = self.attrs.get('Rotate', 0)
    self.annots = self.attrs.get('Annots')
    self.beads = self.attrs.get('B')
    if 'Contents' in self.attrs:
      contents = resolve1(self.attrs['Contents'])
    else:
      contents = []
    if not isinstance(contents, list):
      contents = [ contents ]
    self.contents = contents
    return

  def __repr__(self):
    return '<PDFPage: Resources=%r, MediaBox=%r>' % (self.resources, self.mediabox)


##  XRefs

##  PDFXRef
##
class PDFXRef(object):

  def __init__(self):
    self.offsets = None
    return

  def objids(self):
    return self.offsets.keys()

  def load(self, parser):
    while 1:
      try:
        (pos, line) = parser.nextline()
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
      self.offsets = {}
      for objid in xrange(start, start+nobjs):
        try:
          (_, line) = parser.nextline()
        except PSEOF:
          raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
        f = line.strip().split(' ')
        if len(f) != 3:
          raise PDFNoValidXRef('Invalid XRef format: %r, line=%r' % (parser, line))
        (pos, genno, use) = f
        self.offsets[objid] = (int(genno), long(pos), use)
    self.load_trailer(parser)
    return
  
  def load_trailer(self, parser):
    try:
      (_,kwd) = parser.nexttoken()
      assert kwd == KEYWORD_TRAILER
      (_,dic) = parser.nextobject()
    except PSEOF:
      x = parser.pop(1)
      if not x:
        raise PDFNoValidXRef('Unexpected EOF - file corrupted')
      (_,dic) = x[0]
    self.trailer = dict_value(dic)
    return

  def getpos(self, objid):
    try:
      (genno, pos, use) = self.offsets[objid]
    except KeyError:
      raise
    if use != 'n':
      if STRICT:
        raise PDFValueError('Unused objid=%r' % objid)
    return (None, pos)


##  PDFXRefStream
##
class PDFXRefStream(object):

  def __init__(self):
    self.objid0 = None
    self.objid1 = None
    self.data = None
    self.entlen = None
    self.fl1 = self.fl2 = self.fl3 = None
    return

  def objids(self):
    return range(self.objid0, self.objid1+1)

  def load(self, parser):
    (_,objid) = parser.nexttoken() # ignored
    (_,genno) = parser.nexttoken() # ignored
    (_,kwd) = parser.nexttoken()
    (_,stream) = parser.nextobject()
    if not isinstance(stream, PDFStream) or stream.dic['Type'] != LITERAL_XREF:
      raise PDFNoValidXRef('Invalid PDF stream spec.')
    size = stream.dic['Size']
    (start, nobjs) = stream.dic.get('Index', (0,size))
    self.objid0 = start
    self.objid1 = start+nobjs
    (self.fl1, self.fl2, self.fl3) = stream.dic['W']
    self.data = stream.get_data()
    self.entlen = self.fl1+self.fl2+self.fl3
    self.trailer = stream.dic
    return

  def getpos(self, objid):
    if objid < self.objid0 or self.objid1 <= objid:
      raise KeyError(objid)
    i = self.entlen * (objid-self.objid0)
    ent = self.data[i:i+self.entlen]
    f1 = nunpack(ent[:self.fl1], 1)
    if f1 == 1:
      pos = nunpack(ent[self.fl1:self.fl1+self.fl2])
      genno = nunpack(ent[self.fl1+self.fl2:])
      return (None, pos)
    elif f1 == 2:
      objid = nunpack(ent[self.fl1:self.fl1+self.fl2])
      index = nunpack(ent[self.fl1+self.fl2:])
      return (objid, index)


##  PDFDocument
##
##  A PDFDocument object represents a PDF document.
##  Since a PDF file is usually pretty big, normally it is not loaded
##  at once. Rather it is parsed dynamically as processing goes.
##  A PDF parser is associated with the document.
##
class PDFDocument(object):
  
  def __init__(self, debug=0):
    self.debug = debug
    self.xrefs = []
    self.objs = {}
    self.parsed_objs = {}
    self.root = None
    self.catalog = None
    self.parser = None
    self.encryption = None
    self.decipher = None
    self.ready = False
    return

  # set_parser(parser)
  #   Associates the document with an (already initialized) parser object.
  def set_parser(self, parser):
    if self.parser: return
    self.parser = parser
    # The document is set to be temporarily ready during collecting
    # all the basic information about the document, e.g.
    # the header, the encryption information, and the access rights 
    # for the document.
    self.ready = True
    # Retrieve the information of each header that was appended
    # (maybe multiple times) at the end of the document.
    self.xrefs = list(parser.read_xref())
    for xref in self.xrefs:
      trailer = xref.trailer
      if not trailer: continue
      # If there's an encryption info, remember it.
      if 'Encrypt' in trailer:
        #assert not self.encryption
        self.encryption = (list_value(trailer['ID']),
                           dict_value(trailer['Encrypt']))
      if 'Root' in trailer:
        self.set_root(dict_value(trailer['Root']))
        break
    else:
      raise PDFSyntaxError('No /Root object! - Is this really a PDF?')
    # The document is set to be non-ready again, until all the
    # proper initialization (asking the password key and
    # verifying the access permission, so on) is finished.
    self.ready = False
    return

  # set_root(root)
  #   Set the Root dictionary of the document.
  #   Each PDF file must have exactly one /Root dictionary.
  def set_root(self, root):
    self.root = root
    self.catalog = dict_value(self.root)
    if self.catalog.get('Type') != LITERAL_CATALOG:
      if STRICT:
        raise PDFValueError('Catalog not found!')
    return
  
  # initialize(password='')
  #   Perform the initialization with a given password.
  #   This step is mandatory even if there's no password associated
  #   with the document.
  def initialize(self, password=''):
    if not self.encryption:
      self.is_printable = self.is_modifiable = self.is_extractable = True
      self.ready = True
      return
    (docid, param) = self.encryption
    if literal_name(param['Filter']) != 'Standard':
      raise PDFEncryptionError('Unknown filter: param=%r' % param)
    V = int_value(param.get('V', 0))
    if not (V == 1 or V == 2):
      raise PDFEncryptionError('Unknown algorithm: param=%r' % param)
    length = int_value(param.get('Length', 40)) # Key length (bits)
    O = str_value(param['O'])
    R = int_value(param['R']) # Revision
    if 5 <= R:
      raise PDFEncryptionError('Unknown revision: %r' % R)
    U = str_value(param['U'])
    P = int_value(param['P'])
    self.is_printable = bool(P & 4)        
    self.is_modifiable = bool(P & 8)
    self.is_extractable = bool(P & 16)
    # Algorithm 3.2
    password = (password+PASSWORD_PADDING)[:32] # 1
    hash = md5.md5(password) # 2
    hash.update(O) # 3
    hash.update(struct.pack('<l', P)) # 4
    hash.update(docid[0]) # 5
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
      u1 = Arcfour(key).process(password)
    elif R == 3:
      # Algorithm 3.5
      hash = md5.md5(PASSWORD_PADDING) # 2
      hash.update(docid[0]) # 3
      x = Arcfour(key).process(hash.digest()[:16]) # 4
      for i in xrange(1,19+1):
        k = ''.join( chr(ord(c) ^ i) for c in key )
        x = Arcfour(k).process(x)
      u1 = x+x # 32bytes total
    if R == 2:
      is_authenticated = (u1 == U)
    else:
      is_authenticated = (u1[:16] == U[:16])
    if not is_authenticated:
      raise PDFPasswordIncorrect
    self.decrypt_key = key
    self.decipher = self.decrypt_rc4  # XXX may be AES
    self.ready = True
    return

  def decrypt_rc4(self, objid, genno, data):
    key = self.decrypt_key + struct.pack('<L',objid)[:3]+struct.pack('<L',genno)[:2]
    hash = md5.md5(key)
    key = hash.digest()[:min(len(key),16)]
    return Arcfour(key).process(data)

  def getobj(self, objid):
    if not self.ready:
      raise PDFException('PDFDocument not initialized')
    #assert self.xrefs
    if 2 <= self.debug:
      print >>stderr, 'getobj: objid=%r' % (objid)
    if objid in self.objs:
      genno = 0
      obj = self.objs[objid]
    else:
      for xref in self.xrefs:
        try:
          (strmid, index) = xref.getpos(objid)
          break
        except KeyError:
          pass
      else:
        if STRICT:
          raise PDFValueError('Cannot locate objid=%r' % objid)
        return None
      if strmid:
        stream = stream_value(self.getobj(strmid))
        if stream.dic['Type'] != LITERAL_OBJSTM:
          if STRICT:
            raise PDFSyntaxError('Not a stream object: %r' % stream)
        try:
          n = stream.dic['N']
        except KeyError:
          if STRICT:
            raise PDFSyntaxError('N is not defined: %r' % stream)
          n = 0
        if strmid in self.parsed_objs:
          objs = self.parsed_objs[stream]
        else:
          parser = PDFObjStrmParser(self, stream.get_data(), debug=self.debug)
          objs = []
          try:
            while 1:
              (_,obj) = parser.nextobject()
              objs.append(obj)
          except PSEOF:
            pass
          self.parsed_objs[stream] = objs
        genno = 0
        obj = objs[stream.dic['N']*2+index]
        if isinstance(obj, PDFStream):
          obj.set_objid(objid, 0)
      else:
        self.parser.seek(index)
        (_,objid1) = self.parser.nexttoken() # objid
        (_,genno) = self.parser.nexttoken() # genno
        assert objid1 == objid, (objid, objid1)
        (_,kwd) = self.parser.nexttoken()
        if kwd != KEYWORD_OBJ:
          raise PDFSyntaxError('Invalid object spec: offset=%r' % index)
        (_,obj) = self.parser.nextobject()
        if isinstance(obj, PDFStream):
          obj.set_objid(objid, genno)
      if 2 <= self.debug:
        print >>stderr, 'register: objid=%r: %r' % (objid, obj)
      self.objs[objid] = obj
    if self.decipher:
      obj = decipher_all(self.decipher, objid, genno, obj)
    return obj
  
  INHERITABLE_ATTRS = set(['Resources', 'MediaBox', 'CropBox', 'Rotate'])
  def get_pages(self, debug=0):
    if not self.ready:
      raise PDFException('PDFDocument is not initialized')
    #assert self.xrefs
    def search(obj, parent):
      tree = dict_value(obj).copy()
      for (k,v) in parent.iteritems():
        if k in self.INHERITABLE_ATTRS and k not in tree:
          tree[k] = v
      if tree.get('Type') == LITERAL_PAGES and 'Kids' in tree:
        if 1 <= debug:
          print >>stderr, 'Pages: Kids=%r' % tree['Kids']
        for c in tree['Kids']:
          for x in search(c, tree):
            yield x
      elif tree.get('Type') == LITERAL_PAGE:
        if 1 <= debug:
          print >>stderr, 'Page: %r' % tree
        yield (obj.objid, tree)
    if 'Pages' not in self.catalog: return
    for (pageid,tree) in search(self.catalog['Pages'], self.catalog):
      yield PDFPage(self, pageid, tree)
    return

  def get_outlines(self):
    if 'Outlines' not in self.catalog:
      raise PDFException('No /Outlines defined!')
    def search(entry, level):
      entry = dict_value(entry)
      if 'Title' in entry:
        if 'A' in entry or 'Dest' in entry:
          title = unicode(str_value(entry['Title']), 'utf-8', 'ignore')
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
      raise KeyError((cat,key))
    # may raise KeyError
    d0 = dict_value(names[cat])
    def lookup(d):
      if 'Limits' in d:
        (k1,k2) = list_value(d['Limits'])
        if key < k1 or k2 < key: return None
        if 'Names' in d:
          objs = list_value(d['Names'])
          names = dict(choplist(2, objs))
          return names[key]
      if 'Kids' in d:
        for c in list_value(d['Kids']):
          v = lookup(dict_value(c))
          if v: return v
      raise KeyError((cat,key))
    return lookup(d0)


##  PDFParser
##
class PDFParser(PSStackParser):

  def __init__(self, doc, fp, debug=0):
    PSStackParser.__init__(self, fp, debug=debug)
    self.doc = doc
    self.doc.set_parser(self)
    return

  def __repr__(self):
    return '<PDFParser>'

  def do_keyword(self, pos, token):
    if token in (KEYWORD_XREF, KEYWORD_STARTXREF):
      self.add_results(*self.pop(1))
      return
    if token == KEYWORD_ENDOBJ:
      self.add_results(*self.pop(4))
      return
    
    if token == KEYWORD_R:
      # reference to indirect object
      try:
        ((_,objid), (_,genno)) = self.pop(2)
        (objid, genno) = (int(objid), int(genno))
        obj = PDFObjRef(self.doc, objid, genno)
        self.push((pos, obj))
      except PSSyntaxError:
        pass
      return
      
    if token == KEYWORD_STREAM:
      # stream object
      ((_,dic),) = self.pop(1)
      dic = dict_value(dic)
      try:
        objlen = int_value(dic['Length'])
      except KeyError:
        if STRICT:
          raise PDFValueError('/Length is undefined: %r' % dic)
        objlen = 0
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
      if 1 <= self.debug:
        print >>stderr, 'Stream: pos=%d, objlen=%d, dic=%r, data=%r...' % \
              (pos, objlen, dic, data[:10])
      obj = PDFStream(dic, data, self.doc.decipher)
      self.push((pos, obj))
      return
    
    # others
    self.push((pos, token))
    return

  def find_xref(self):
    # search the last xref table by scanning the file backwards.
    prev = None
    for line in self.revreadlines():
      line = line.strip()
      if 2 <= self.debug:
        print >>stderr, 'find_xref: %r' % line
      if line == 'startxref': break
      if line:
        prev = line
    else:
      raise PDFNoValidXRef('Unexpected EOF')
    if 1 <= self.debug:
      print >>stderr, 'xref found: pos=%r' % prev
    self.seek(long(prev))
    return

  # read xref tables and trailers
  def read_xref(self):
    try:
      self.find_xref()
      while 1:
        # read xref table
        try:
          (pos, token) = self.nexttoken()
        except PSEOF:
          raise PDFNoValidXRef('Unexpected EOF')
        if 2 <= self.debug:
          print >>stderr, 'read_xref: %r' % token
        if isinstance(token, int):
          # XRefStream: PDF-1.5
          self.seek(pos)
          self.reset()
          xref = PDFXRefStream()
          xref.load(self)
        else:
          if token != KEYWORD_XREF:
            raise PDFNoValidXRef('xref not found: pos=%d, token=%r' % 
                                 (pos, token))
          self.nextline()
          xref = PDFXRef()
          xref.load(self)
        yield xref
        trailer = xref.trailer
        if not trailer: continue
        if 1 <= self.debug:
          print >>stderr, 'trailer: %r' % trailer
        if 'XRefStm' in trailer:
          self.seek(int_value(trailer['XRefStm']))
        if 'Prev' in trailer:
          # find previous xref
          pos = int_value(trailer['Prev'])
          self.seek(pos)
          if 1 <= self.debug:
            print >>stderr, 'prev trailer: pos=%d' % pos
        else:
          break
    except PDFNoValidXRef:
      # fallback
      if 1 <= self.debug:
        print >>stderr, 'no xref, fallback'
      self.seek(0)
      pat = re.compile(r'^(\d+)\s+(\d+)\s+obj\b')
      offsets = {}
      xref = PDFXRef()
      while 1:
        try:
          (pos, line) = self.nextline()
        except PSEOF:
          break
        if line.startswith('trailer'): break
        m = pat.match(line)
        if not m: continue
        (objid, genno) = m.groups()
        offsets[int(objid)] = (0, pos, 'f')
      if not offsets: raise
      xref.offsets = offsets
      xref.objid0 = min(offsets.iterkeys())
      xref.objid1 = max(offsets.iterkeys())
      self.seek(pos)
      xref.load_trailer(self)
      if 1 <= self.debug:
        print >>stderr, 'trailer: %r' % xref.trailer
      yield xref
    return

##  PDFObjStrmParser
##
class PDFObjStrmParser(PDFParser):
  def __init__(self, doc, data, debug=0):
    try:
      from cStringIO import StringIO
    except ImportError:
      from StringIO import StringIO
    PDFParser.__init__(self, doc, StringIO(data), debug=debug)
    return
  
  def flush(self):
    self.add_results(*self.popall())
    return
