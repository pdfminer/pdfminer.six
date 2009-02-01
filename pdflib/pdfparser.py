#!/usr/bin/env python

# pdfparser.py, Yusuke Shinyama
#  ver 0.1, Dec 24 2004-
#  ver 0.2, Dec 24 2007

import sys, re
import md5, struct
stderr = sys.stderr
from pdflib.utils import choplist, nunpack, decode_text
from pdflib.arcfour import Arcfour
from pdflib.psparser import PSStackParser, PSSyntaxError, PSEOF, \
     PSLiteralTable, PSKeywordTable, literal_name, keyword_name, \
     STRICT
from pdflib.pdftypes import PDFException, PDFTypeError, PDFNotImplementedError, \
     PDFStream, PDFObjRef, resolve1, decipher_all, \
     int_value, float_value, num_value, str_value, list_value, dict_value, stream_value


##  Exceptions
##
class PDFSyntaxError(PDFException): pass
class PDFNoValidXRef(PDFSyntaxError): pass
class PDFEncryptionError(PDFException): pass
class PDFPasswordIncorrect(PDFEncryptionError): pass

# some predefined literals and keywords.
LITERAL_OBJSTM = PSLiteralTable.intern('ObjStm')
LITERAL_XREF = PSLiteralTable.intern('XRef')
LITERAL_PAGE = PSLiteralTable.intern('Page')
LITERAL_PAGES = PSLiteralTable.intern('Pages')
LITERAL_CATALOG = PSLiteralTable.intern('Catalog')


##  XRefs
##

##  PDFXRef
##
class PDFXRef(object):

  def __init__(self):
    self.offsets = None
    return

  def __repr__(self):
    return '<PDFXRef: objs=%d>' % len(self.offsets)

  def objids(self):
    return self.offsets.iterkeys()

  def load(self, parser, debug=0):
    self.offsets = {}
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
      for objid in xrange(start, start+nobjs):
        try:
          (_, line) = parser.nextline()
        except PSEOF:
          raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
        f = line.strip().split(' ')
        if len(f) != 3:
          raise PDFNoValidXRef('Invalid XRef format: %r, line=%r' % (parser, line))
        (pos, genno, use) = f
        if use != 'n': continue
        self.offsets[objid] = (int(genno), long(pos))
    if debug:
      print >>stderr, 'xref objects:', self.offsets
    self.load_trailer(parser)
    return
  
  KEYWORD_TRAILER = PSKeywordTable.intern('trailer')
  def load_trailer(self, parser):
    try:
      (_,kwd) = parser.nexttoken()
      assert kwd is self.KEYWORD_TRAILER
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
      (genno, pos) = self.offsets[objid]
    except KeyError:
      raise
    return (None, pos)


##  PDFXRefStream
##
class PDFXRefStream(object):

  def __init__(self):
    self.objid_first = None
    self.objid_last = None
    self.data = None
    self.entlen = None
    self.fl1 = self.fl2 = self.fl3 = None
    return

  def __repr__(self):
    return '<PDFXRef: objid=%d-%d>' % (self.objid_first, self.objid_last)

  def objids(self):
    return xrange(self.objid_first, self.objid_last+1)

  def load(self, parser, debug=0):
    (_,objid) = parser.nexttoken() # ignored
    (_,genno) = parser.nexttoken() # ignored
    (_,kwd) = parser.nexttoken()
    (_,stream) = parser.nextobject()
    if not isinstance(stream, PDFStream) or stream.dic['Type'] is not LITERAL_XREF:
      raise PDFNoValidXRef('Invalid PDF stream spec.')
    size = stream.dic['Size']
    (start, nobjs) = stream.dic.get('Index', (0,size))
    self.objid_first = start
    self.objid_last = start+nobjs-1
    (self.fl1, self.fl2, self.fl3) = stream.dic['W']
    self.data = stream.get_data()
    self.entlen = self.fl1+self.fl2+self.fl3
    self.trailer = stream.dic
    if debug:
      print >>stderr, ('xref stream: objid=%d-%d, fields=%d,%d,%d' %
                       (self.objid_first, self.objid_last, self.fl1, self.fl2, self.fl3))
    return

  def getpos(self, objid):
    if objid < self.objid_first or self.objid_last < objid:
      raise KeyError(objid)
    i = self.entlen * (objid-self.objid_first)
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
    # this is a free object
    raise KeyError(objid)


##  PDFPage
##
class PDFPage(object):
  
  def __init__(self, doc, pageid, attrs):
    self.doc = doc
    self.pageid = pageid
    self.attrs = dict_value(attrs)
    self.lastmod = resolve1(self.attrs.get('LastModified'))
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


##  PDFDocument
##
##  A PDFDocument object represents a PDF document.
##  Since a PDF file is usually pretty big, normally it is not loaded
##  at once. Rather it is parsed dynamically as processing goes.
##  A PDF parser is associated with the document.
##
class PDFDocument(object):

  debug = 0
  
  def __init__(self):
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
    self.xrefs = parser.read_xref()
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
    password = (password+self.PASSWORD_PADDING)[:32] # 1
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
      hash = md5.md5(self.PASSWORD_PADDING) # 2
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

  KEYWORD_OBJ = PSKeywordTable.intern('obj')
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
          raise PDFSyntaxError('Cannot locate objid=%r' % objid)
        return None
      if strmid:
        stream = stream_value(self.getobj(strmid))
        if stream.dic.get('Type') is not LITERAL_OBJSTM:
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
          parser = PDFObjStrmParser(self, stream.get_data())
          objs = []
          try:
            while 1:
              (_,obj) = parser.nextobject()
              objs.append(obj)
          except PSEOF:
            pass
          self.parsed_objs[stream] = objs
        genno = 0
        i = n*2+index
        try:
          obj = objs[i]
        except IndexError:
          raise PDFSyntaxError('Invalid object number: objid=%r' % (objid))
        if isinstance(obj, PDFStream):
          obj.set_objid(objid, 0)
      else:
        self.parser.seek(index)
        (_,objid1) = self.parser.nexttoken() # objid
        (_,genno) = self.parser.nexttoken() # genno
        #assert objid1 == objid, (objid, objid1)
        (_,kwd) = self.parser.nexttoken()
        if kwd is not self.KEYWORD_OBJ:
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
  def get_pages(self):
    if not self.ready:
      raise PDFException('PDFDocument is not initialized')
    #assert self.xrefs
    def search(obj, parent):
      tree = dict_value(obj).copy()
      for (k,v) in parent.iteritems():
        if k in self.INHERITABLE_ATTRS and k not in tree:
          tree[k] = v
      if tree.get('Type') is LITERAL_PAGES and 'Kids' in tree:
        if 1 <= self.debug:
          print >>stderr, 'Pages: Kids=%r' % tree['Kids']
        for c in tree['Kids']:
          for x in search(c, tree):
            yield x
      elif tree.get('Type') is LITERAL_PAGE:
        if 1 <= self.debug:
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

  def __init__(self, doc, fp):
    PSStackParser.__init__(self, fp)
    self.doc = doc
    self.doc.set_parser(self)
    return

  def __repr__(self):
    return '<PDFParser>'

  KEYWORD_R = PSKeywordTable.intern('R')
  KEYWORD_ENDOBJ = PSKeywordTable.intern('endobj')
  KEYWORD_STREAM = PSKeywordTable.intern('stream')
  KEYWORD_XREF = PSKeywordTable.intern('xref')
  KEYWORD_STARTXREF = PSKeywordTable.intern('startxref')
  def do_keyword(self, pos, token):
    if token in (self.KEYWORD_XREF, self.KEYWORD_STARTXREF):
      self.add_results(*self.pop(1))
      return
    if token is self.KEYWORD_ENDOBJ:
      self.add_results(*self.pop(4))
      return
    
    if token is self.KEYWORD_R:
      # reference to indirect object
      try:
        ((_,objid), (_,genno)) = self.pop(2)
        (objid, genno) = (int(objid), int(genno))
        obj = PDFObjRef(self.doc, objid, genno)
        self.push((pos, obj))
      except PSSyntaxError:
        pass
      return
      
    if token is self.KEYWORD_STREAM:
      # stream object
      ((_,dic),) = self.pop(1)
      dic = dict_value(dic)
      try:
        objlen = int_value(dic['Length'])
      except KeyError:
        if STRICT:
          raise PDFSyntaxError('/Length is undefined: %r' % dic)
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
    return long(prev)

  # read xref table
  def read_xref_from(self, start, xrefs):
    self.seek(start)
    self.reset()
    try:
      (pos, token) = self.nexttoken()
    except PSEOF:
      raise PDFNoValidXRef('Unexpected EOF')
    if 2 <= self.debug:
      print >>stderr, 'read_xref_from: start=%d, token=%r' % (start, token)
    if isinstance(token, int):
      # XRefStream: PDF-1.5
      self.seek(pos)
      self.reset()
      xref = PDFXRefStream()
      xref.load(self, debug=self.debug)
    else:
      if token is not self.KEYWORD_XREF:
        raise PDFNoValidXRef('xref not found: pos=%d, token=%r' % 
                             (pos, token))
      self.nextline()
      xref = PDFXRef()
      xref.load(self, debug=self.debug)
    xrefs.append(xref)
    trailer = xref.trailer
    if 1 <= self.debug:
      print >>stderr, 'trailer: %r' % trailer
    if 'XRefStm' in trailer:
      pos = int_value(trailer['XRefStm'])
      self.read_xref_from(pos, xrefs)
    if 'Prev' in trailer:
      # find previous xref
      pos = int_value(trailer['Prev'])
      self.read_xref_from(pos, xrefs)
    return
    
  # read xref tables and trailers
  def read_xref(self):
    xrefs = []
    try:
      pos = self.find_xref()
      self.read_xref_from(pos, xrefs)
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
        offsets[int(objid)] = (0, pos)
      if not offsets: raise
      xref.offsets = offsets
      self.seek(pos)
      xref.load_trailer(self)
      if 1 <= self.debug:
        print >>stderr, 'trailer: %r' % xref.trailer
      xrefs.append(xref)
    return xrefs


##  PDFObjStrmParser
##
class PDFObjStrmParser(PDFParser):
  
  def __init__(self, doc, data):
    try:
      from cStringIO import StringIO
    except ImportError:
      from StringIO import StringIO
    PDFParser.__init__(self, doc, StringIO(data))
    return
  
  def flush(self):
    self.add_results(*self.popall())
    return
