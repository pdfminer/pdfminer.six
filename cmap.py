#!/usr/bin/env python
import sys
stderr = sys.stderr
from struct import pack, unpack
from utils import choplist, nunpack
from psparser import PSException, PSSyntaxError, PSTypeError, PSEOF, \
     PSLiteral, PSKeyword, literal_name, keyword_name, \
     PSStackParser
try:
  import cdb
except ImportError:
  import pycdb as cdb


class CMapError(Exception): pass


##  CMap
##
class CMap:
  
  def __init__(self, debug=0):
    self.debug = debug
    self.code2cid = {}
    self.cid2code = {}
    self.attrs = {}
    return

  def __repr__(self):
    return '<CMap: %s>' % self.attrs.get('CMapName')

  def update(self, code2cid=None, cid2code=None):
    if code2cid:
      self.code2cid.update(code2cid)
    if cid2code:
      self.cid2code.update(cid2code)
    return self
    
  def copycmap(self, cmap):
    self.code2cid.update(cmap.getall_code2cid())
    self.cid2code.update(cmap.getall_cid2code())
    return self

  def register_code2cid(self, code, cid):
    if isinstance(code, str) and isinstance(cid, int):
      self.code2cid[code] = cid
    return self

  def register_cid2code(self, cid, code):
    from glyphlist import charname2unicode
    if isinstance(cid, int):
      if isinstance(code, PSLiteral):
        self.cid2code[cid] = pack('>H', charname2unicode[code.name])
      elif isinstance(code, str):
        self.cid2code[cid] = code
    return self

  def decode(self, bytes):
    if self.debug:
      print >>stderr, 'decode: %r, %r' % (self, bytes)
    x = ''
    for c in bytes:
      if x:
        if x+c in self.code2cid:
          yield self.code2cid[x+c]
        x = ''
      elif c in self.code2cid:
        yield self.code2cid[c]
      else:
        x = c
    return
  
  def is_vertical(self):
    return self.attrs.get('WMode', '0') == '1'

  def tocid(self, code):
    return self.code2cid.get(code)
  def tocode(self, cid):
    return self.cid2code.get(cid)

  def getall_attrs(self):
    return self.attrs.iteritems()
  def getall_code2cid(self):
    return self.code2cid.iteritems()
  def getall_cid2code(self):
    return self.cid2code.iteritems()

  
##  CDBCMap
##
class CDBCMap(CMap):
  
  def __init__(self, cdbname, debug=0):
    CMap.__init__(self, debug=debug)
    self.cdbname = cdbname
    self.db = cdb.init(cdbname)
    return

  def __repr__(self):
    return '<CDBCMap: %s (%r)>' % (self.db['/CMapName'], self.cdbname)

  def tocid(self, code):
    k = 'c'+code
    if not self.db.has_key(k):
      return None
    return unpack('>L', self.db[k])
  def tocode(self, cid):
    k = 'i'+pack('>L', cid)
    if not self.db.has_key(k):
      return None
    return self.db[k]
  
  def is_vertical(self):
    return (self.db.has_key('/WMode') and
            self.db['/WMode'] == '1')

  def getall(self, c):
    while 1:
      x = self.db.each()
      if not x: break
      (k,v) = x
      if k.startswith(c):
        yield (k[1:], unpack('>L', v)[0])
    return

  def getall_attrs(self):
    while 1:
      x = self.db.each()
      if not x: break
      (k,v) = x
      if k.startswith('/'):
        yield (k[1:], eval(v)[0])
    return
  
  def getall_cid2code(self):
    return self.getall('i')
  def getall_code2cid(self):
    return self.getall('c')

  def decode(self, bytes):
    if self.debug:
      print >>stderr, 'decode: %r, %r' % (self, bytes)
    x = ''
    for c in bytes:
      if x:
        if x+c in self.code2cid:
          yield self.code2cid[x+c]
        elif self.db.has_key('c'+x+c):
          (dest,) = unpack('>L', self.db['c'+x+c])
          self.code2cid[x+c] = dest
          yield dest
        x = ''
      elif c in self.code2cid:
        yield self.code2cid[c]
      elif self.db.has_key('c'+c):
        (dest,) = unpack('>L', self.db['c'+c])
        self.code2cid[c] = dest
        yield dest
      else:
        x = c
    return


##  CMapDB
##
class CMapDB:

  class CMapNotFound(CMapError): pass
  
  CMAP_ALIAS = {
    }
  
  debug = 0
  dirname = None
  cdbdirname = None
  cmapdb = {}

  @classmethod
  def initialize(klass, dirname, cdbdirname=None, debug=0):
    klass.dirname = dirname
    klass.cdbdirname = cdbdirname or dirname
    klass.debug = debug
    return

  @classmethod
  def get_cmap(klass, cmapname, strict=True):
    import os.path
    cmapname = klass.CMAP_ALIAS.get(cmapname, cmapname)
    if cmapname in klass.cmapdb:
      cmap = klass.cmapdb[cmapname]
    else:
      fname = os.path.join(klass.dirname, cmapname)
      cdbname = os.path.join(klass.cdbdirname, cmapname+'.cmap.cdb')
      if os.path.exists(cdbname):
        if 1 <= klass.debug:
          print >>stderr, 'Opening: CDBCMap %r...' % cdbname
        cmap = CDBCMap(cdbname)
      elif os.path.exists(fname):
        if 1 <= klass.debug:
          print >>stderr, 'Reading: CMap %r...' % fname
        cmap = CMap()
        fp = file(fname)
        CMapParser(cmap, fp, debug=klass.debug).run()
        fp.close()
      elif not strict:
        cmap = CMap() # just create empty cmap
      else:
        raise CMapDB.CMapNotFound(cmapname)
      klass.cmapdb[cmapname] = cmap
    return cmap


##  CMapParser
##
class CMapParser(PSStackParser):

  def __init__(self, cmap, fp, debug=0):
    PSStackParser.__init__(self, fp, debug=debug)
    self.cmap = cmap
    self.in_cmap = False
    return

  def run(self):
    try:
      self.nextobject()
    except PSEOF:
      pass
    return

  def do_keyword(self, pos, token):
    name = token.name
    if name == 'begincmap':
      self.in_cmap = True
      self.popall()
      return
    elif name == 'endcmap':
      self.in_cmap = False
      return
    if not self.in_cmap: return
    #
    if name == 'def':
      try:
        ((_,k),(_,v)) = self.pop(2)
        self.cmap.attrs[str(k)] = v
      except PSSyntaxError:
        pass
      return
    
    if name == 'usecmap':
      try:
        ((_,cmapname),) = self.pop(1)
        self.cmap.copycmap(CMapDB.get_cmap(literal_name(cmapname)))
      except PSSyntaxError:
        pass
      return
      
    if name == 'begincodespacerange':
      self.popall()
      return
    if name == 'endcodespacerange':
      self.popall()
      return
    
    if name == 'begincidrange':
      self.popall()
      return
    if name == 'endcidrange':
      objs = [ obj for (_,obj) in self.popall() ]
      for (s,e,cid) in choplist(3, objs):
        if (not isinstance(s, str) or not isinstance(e, str) or
            not isinstance(cid, int) or len(s) != len(e)): continue
        sprefix = s[:-4]
        eprefix = e[:-4]
        if sprefix != eprefix: continue
        svar = s[-4:]
        evar = e[-4:]
        s1 = nunpack(svar)
        e1 = nunpack(evar)
        vlen = len(svar)
        #assert s1 <= e1
        for i in xrange(e1-s1+1):
          x = sprefix+pack('>L',s1+i)[-vlen:]
          self.cmap.register_code2cid(x, cid+i)
      return
    
    if name == 'begincidchar':
      self.popall()
      return
    if name == 'endcidchar':
      objs = [ obj for (_,obj) in self.popall() ]
      for (cid,code) in choplist(2, objs):
        if isinstance(code, str) and isinstance(cid, str):
          self.cmap.register_code2cid(code, nunpack(cid))
      return
        
    if name == 'beginbfrange':
      self.popall()
      return
    if name == 'endbfrange':
      objs = [ obj for (_,obj) in self.popall() ]
      for (s,e,code) in choplist(3, objs):
        if (not isinstance(s, str) or not isinstance(e, str) or
            len(s) != len(e)): continue
        s1 = nunpack(s)
        e1 = nunpack(e)
        #assert s1 <= e1
        if isinstance(code, list):
          for i in xrange(e1-s1+1):
            self.cmap.register_cid2code(s1+i, code[i])
        else:
          var = code[-4:]
          base = nunpack(var)
          prefix = code[:-4]
          vlen = len(var)
          for i in xrange(e1-s1+1):
            x = prefix+pack('>L',base+i)[-vlen:]
            self.cmap.register_cid2code(s1+i, x)
      return
        
    if name == 'beginbfchar':
      self.popall()
      return
    if name == 'endbfchar':
      objs = [ obj for (_,obj) in self.popall() ]
      for (cid,code) in choplist(2, objs):
        if isinstance(cid, str) and isinstance(code, str):
          self.cmap.register_cid2code(nunpack(cid), code)
      return
        
    if name == 'beginnotdefrange':
      self.popall()
      return
    if name == 'endnotdefrange':
      self.popall()
      return

    self.push((pos, token))
    return


##  FontMetricsDB
##
class FontMetricsDB:
  from fontmetrics import FONT_METRICS
  
  @classmethod
  def get_metrics(klass, fontname):
    return klass.FONT_METRICS[fontname]


##  EncodingDB
##
class EncodingDB:
      
  from glyphlist import charname2unicode
  from latin_enc import ENCODING
  
  std2unicode = {}
  mac2unicode = {}
  win2unicode = {}
  pdf2unicode = {}
  for (name,std,mac,win,pdf) in ENCODING:
    c = unichr(charname2unicode[name])
    if std: std2unicode[std] = c
    if mac: mac2unicode[mac] = c
    if win: win2unicode[win] = c
    if pdf: pdf2unicode[pdf] = c
  
  encodings = {
    'StandardEncoding': std2unicode,
    'MacRomanEncoding': mac2unicode,
    'WinAnsiEncoding': win2unicode,
    'PDFDocEncoding': pdf2unicode,
    }
  
  @classmethod
  def get_encoding(klass, name, diff=None):
    cid2unicode = klass.encodings.get(name, klass.std2unicode)
    if diff:
      cid2unicode = cid2unicode.copy()
      cid = 0
      for x in diff:
        if isinstance(x, int):
          cid = x
        elif isinstance(x, PSLiteral):
          try:
            cid2unicode[cid] = unichr(EncodingDB.charname2unicode[x.name])
          except KeyError:
            pass
          cid += 1
    return cid2unicode
