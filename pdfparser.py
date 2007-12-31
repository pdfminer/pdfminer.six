#!/usr/bin/env python

# pdfparser.py, Yusuke Shinyama
#  ver 0.1, Dec 24 2004-
#  ver 0.2, Dec 24 2007

# TODO:
#   - Code Documentation.
#   - Error handling for invalid type.

#   - Outlines.
#   - Named Objects. (pages)
#   - Writers.
#   - Linearized PDF.
#   - Encryption?

import sys, re
from struct import pack, unpack
try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO
try:
  import cdb
except ImportError:
  import pycdb as cdb
stderr = sys.stderr


##  Utilities
##
def choplist(n, seq):
  '''Groups every n elements of the list.'''
  r = []
  for x in seq:
    r.append(x)
    if len(r) == n:
      yield tuple(r)
      r = []
  return

def nunpack(s, default=0):
  '''Unpacks up to 4 bytes.'''
  l = len(s)
  if not l:
    return default
  elif l == 1:
    return ord(s)
  elif l == 2:
    return unpack('>H', s)[0]
  elif l == 3:
    return unpack('>L', '\x00'+s)[0]
  elif l == 4:
    return unpack('>L', s)[0]
  else:
    return TypeError('invalid length: %d' % l)

def mult_matrix((a1,b1,c1,d1,e1,f1), (a0,b0,c0,d0,e0,f0)):
  '''Multiplies two matrices.'''
  return (a0*a1+c0*b1,    b0*a1+d0*b1,
          a0*c1+c0*d1,    b0*c1+d0*d1,
          a0*e1+c0*f1+e0, b0*e1+d0*f1+f0)

def apply_matrix((a,b,c,d,e,f), (x,y)):
  '''Applies a matrix to a coordination.'''
  return (a*x+c*y+e, b*x+d*y+f)


##  Exceptions
##
class PSException(Exception): pass
class PSSyntaxError(PSException): pass
class PSTypeError(PSException): pass
class PSValueError(PSException): pass
class PDFException(PSException): pass
class PDFSyntaxError(PDFException): pass
class PDFEncrypted(PDFException): pass
class PDFTypeError(PDFException): pass
class PDFValueError(PDFException): pass
class PDFResourceError(PDFException): pass
class PDFInterpreterError(PDFException): pass
class PDFFontError(PDFException): pass
class PDFUnicodeNotDefined(PDFFontError): pass


##  PostScript Types
##
class PSLiteral:
  '''
  PS literals (e.g. "/Name").
  Caution: Never create these objects directly.
  Use PSLiteralTable.intern() instead.
  '''
  def __init__(self, name):
    self.name = name
    return
  def __repr__(self):
    return '/%s' % self.name

class PSKeyword:
  '''
  PS keywords (e.g. "showpage").
  Caution: Never create these objects directly.
  Use PSKeywordTable.intern() instead.
  '''
  def __init__(self, name):
    self.name = name
    return
  def __repr__(self):
    return self.name

class PSSymbolTable:
  '''
  Symbol table that stores PSLiteral or PSKeyword.
  '''
  def __init__(self, classe):
    self.dic = {}
    self.classe = classe
    return
  
  def intern(self, name):
    if name in self.dic:
      lit = self.dic[name]
    else:
      lit = self.classe(name)
      self.dic[name] = lit
    return lit

PSLiteralTable = PSSymbolTable(PSLiteral)
PSKeywordTable = PSSymbolTable(PSKeyword)

# some predefined literals and keywords.
LITERAL_OBJSTM = PSLiteralTable.intern('ObjStm')
LITERAL_PDF = PSLiteralTable.intern('PDF')
LITERAL_TEXT = PSLiteralTable.intern('Text')
LITERAL_XREF = PSLiteralTable.intern('XRef')
LITERAL_FONT = PSLiteralTable.intern('Font')
LITERAL_PAGE = PSLiteralTable.intern('Page')
LITERAL_FORM = PSLiteralTable.intern('Form')
LITERAL_PAGES = PSLiteralTable.intern('Pages')
LITERAL_CATALOG = PSLiteralTable.intern('Catalog')
LITERAL_FLATE_DECODE = PSLiteralTable.intern('FlateDecode')
LITERAL_STANDARD_ENCODING = PSLiteralTable.intern('StandardEncoding')
KEYWORD_OBJ = PSKeywordTable.intern('obj')
KEYWORD_EI = PSKeywordTable.intern('EI')


##  CMap
##
class CMap:
  
  def __init__(self, debug=0):
    self.debug = 0
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
    assert isinstance(code, str)
    assert isinstance(cid, int)
    self.code2cid[code] = cid
    return self

  def register_cid2code(self, cid, code):
    from glyphlist import charname2unicode
    assert isinstance(cid, int)
    if isinstance(code, PSLiteral):
      code = pack('>H', charname2unicode[code.name])
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
  def get_cmap(klass, cmapname):
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
        CMapParser(cmap, fp).parse()
        fp.close()
      klass.cmapdb[cmapname] = cmap
    return cmap


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
  

##  Color Spaces
##
LITERAL_DEVICE_GRAY = PSLiteralTable.intern('DeviceGray')
LITERAL_DEVICE_RGB = PSLiteralTable.intern('DeviceRGB')
LITERAL_DEVICE_CMYK = PSLiteralTable.intern('DeviceCMYK')
LITERAL_ICC_BASED = PSLiteralTable.intern('ICCBased')
LITERAL_DEVICE_N = PSLiteralTable.intern('DeviceN')
CS_COMPONENTS = {
  PSLiteralTable.intern('CalRGB'): 3,
  PSLiteralTable.intern('CalGray'): 1,
  PSLiteralTable.intern('Lab'): 3,
  PSLiteralTable.intern('DeviceRGB'): 3,
  PSLiteralTable.intern('DeviceCMYK'): 4,
  PSLiteralTable.intern('DeviceGray'): 1,
  PSLiteralTable.intern('Separation'): 1,
  PSLiteralTable.intern('Indexed'): 1,
  PSLiteralTable.intern('Pattern'): 1,
  }

def cs_params(cs):
  t = cs[0]
  if t == LITERAL_ICC_BASED:
    return stream_value(cs[1]).dic['N']
  elif t == LITERAL_DEVICE_N:
    return len(list_value(cs[1]))
  else:
    return CS_COMPONENTS[t]


##  PSBaseParser
##
class PSBaseParser:

  '''PostScript parser that performs only basic tokenization.'''

  def __init__(self, fp, debug=0):
    self.fp = fp
    self.debug = debug
    self.bufsize = 4096
    self.seek(0)
    return

  def __repr__(self):
    return '<PSBaseParser: %r>' % (self.fp,)

  def seek(self, pos):
    '''
    seeks to the given pos.
    '''
    if 2 <= self.debug:
      print >>stderr, 'seek:', pos
    self.fp.seek(pos)
    self.linepos = pos
    self.linebuf = None
    self.curpos = 0
    self.line = ''
    return
  
  EOLCHAR = re.compile(r'[\r\n]')
  def nextline(self):
    '''
    fetches the next line that ends either with \\r or \\n.
    '''
    line = ''
    eol = None
    while 1:
      if not self.linebuf or len(self.linebuf) <= self.curpos:
        # fetch next chunk.
        self.linebuf = self.fp.read(self.bufsize)
        if not self.linebuf:
          # at EOF.
          break
        self.curpos = 0
      if eol:
        c = self.linebuf[self.curpos]
        # handle '\r\n'
        if (eol == '\r' and c == '\n'):
          line += c
          self.curpos += 1
        break
      m = self.EOLCHAR.search(self.linebuf, self.curpos)
      if m:
        i = m.end(0)
        line += self.linebuf[self.curpos:i]
        eol = self.linebuf[i-1]
        self.curpos = i
      else:
        # fetch further
        line += self.linebuf[self.curpos:]
        self.linebuf = None
    self.linepos += len(line)
    return line

  def revreadlines(self):
    '''
    fetches lines backword. used to locate trailers.
    '''
    self.fp.seek(0, 2)
    pos = self.fp.tell()
    buf = ''
    while 0 < pos:
      pos = max(0, pos-self.bufsize)
      self.fp.seek(pos)
      s = self.fp.read(self.bufsize)
      if not s: break
      while 1:
        n = max(s.rfind('\r'), s.rfind('\n'))
        if n == -1:
          buf = s + buf
          break
        yield buf+s[n:]
        s = s[:n]
        buf = ''
    return

  SPECIAL = r'%\[\]()<>{}/\000\011\012\014\015\040'
  TOKEN = re.compile(r'<<|>>|[%\[\]()<>{}/]|[^'+SPECIAL+r']+')
  LITERAL = re.compile(r'([^#'+SPECIAL+r']|#[0-9abcdefABCDEF]{2})+')
  NUMBER = re.compile(r'[+-]?[0-9][.0-9]*$')
  STRING_NORM = re.compile(r'(\\[0-9]{1,3}|\\.|[^\)])+')
  STRING_NORM_SUB = re.compile(r'\\[0-7]{1,3}|\\.')
  STRING_HEX = re.compile(r'[\s0-9a-fA-F]+')
  STRING_HEX_SUB = re.compile(r'[0-9a-fA-F]{1,2}')

  def parse(self):
    '''
    Yields a list of basic tokens: keywords, literals, strings, 
    numbers and parentheses. Comments are skipped.
    Nested objects (i.e. arrays and dictionaries) are not handled.
    '''
    while 1:
      # do not strip line! we need to distinguish last '\n' or '\r'
      linepos0 = self.linepos
      self.line = self.nextline()
      if not self.line: break
      if 2 <= self.debug:
        print >>stderr, 'line: (%d) %r' % (self.linepos, self.line)
      # do this before removing comment
      if self.line.startswith('%%EOF'): break
      charpos = 0
      
      # tokenize
      while 1:
        m = self.TOKEN.search(self.line, charpos)
        if not m: break
        t = m.group(0)
        pos = linepos0 + m.start(0)
        charpos = m.end(0)
        
        if t == '%':
          # skip comment
          if 2 <= self.debug:
            print >>stderr, 'comment: %r' % self.line[charpos:]
          break
        
        elif t == '/':
          # literal object
          mn = self.LITERAL.match(self.line, m.start(0)+1)
          lit = PSLiteralTable.intern(mn.group(0))
          yield (pos, lit)
          charpos = mn.end(0)
          if 2 <= self.debug:
            print >>stderr, 'name: %r' % lit
            
        elif t == '(':
          # normal string object
          s = ''
          while 1:
            ms = self.STRING_NORM.match(self.line, charpos)
            if not ms: break
            s1 = ms.group(0)
            charpos = ms.end(0)
            if len(s1) == 1 and s1[-1] == '\\':
              s += s1[-1:]
              self.line = self.nextline()
              if not self.line:
                raise PSSyntaxError('end inside string: linepos=%d, line=%r' %
                                    (self.linepos, self.line))
              charpos = 0
            elif charpos == len(self.line):
              s += s1
              self.line = self.nextline()
              if not self.line:
                raise PSSyntaxError('end inside string: linepos=%d, line=%r' %
                                    (self.linepos, self.line))
              charpos = 0
            else:
              s += s1
              break
          if self.line[charpos] != ')':
            raise PSSyntaxError('no close paren: linepos=%d, line=%r' %
                                (self.linepos, self.line))
          charpos += 1
          def convesc(m):
            x = m.group(0)
            if x[1:].isdigit():
              return chr(int(x[1:], 8))
            else:
              return x[1]
          s = self.STRING_NORM_SUB.sub(convesc, s)
          if 2 <= self.debug:
            print >>stderr, 'str: %r' % s
          yield (pos, s)
          
        elif t == '<':
          # hex string object
          ms = self.STRING_HEX.match(self.line, charpos)
          charpos = ms.end(0)
          if self.line[charpos] != '>':
            raise PSSyntaxError('no close paren: linepos=%d, line=%r' %
                                (self.linepos, self.line))
          charpos += 1
          def convhex(m1):
            return chr(int(m1.group(0), 16))
          s = self.STRING_HEX_SUB.sub(convhex, ms.group(0))
          if 2 <= self.debug:
            print >>stderr, 'str: %r' % s
          yield (pos, s)

        elif self.NUMBER.match(t):
          # number
          if '.' in t:
            n = float(t)
          else:
            n = int(t)
          if 2 <= self.debug:
            print >>stderr, 'number: %r' % n
          yield (pos, n)

        elif t in ('true','false'):
          # boolean
          if 2 <= self.debug:
            print >>stderr, 'boolean: %r' % t
          yield (pos, (t == 'true'))
        
        else:
          # other token
          if 2 <= self.debug:
            print >>stderr, 'keyword: %r' % t
          yield (pos, PSKeywordTable.intern(t))

    return


##  PSStackParser
##
class PSStackParser(PSBaseParser):

  '''
  PostScript parser that recognizes compound objects
  such as arrays and dictionaries.
  '''
  
  def __init__(self, fp, debug=0):
    PSBaseParser.__init__(self, fp, debug=debug)
    self.context = []
    self.partobj = None
    return

  def do_token(self, pos, token):
    '''
    Handles special tokens.
    Returns true if the token denotes the end of an object.
    '''
    return False

  def push(self, obj):
    '''
    Push an object to the stack.
    '''
    self.partobj.append(obj)
    return

  def pop(self, n):
    '''
    Pop N objects from the stack.
    '''
    if len(self.partobj) < n:
      raise PSSyntaxError('stack too short < %d' % n)
    r = self.partobj[-n:]
    self.partobj = self.partobj[:-n]
    return r
  
  def popall(self):
    '''
    Discards all the objects on the stack.
    '''
    self.partobj = []
    return

  def parse(self):
    '''
    Yields a list of objects: keywords, literals, strings, 
    numbers, arrays and dictionaries. Arrays and dictionaries
    are represented as Python sequence and dictionaries.
    '''
    
    def startobj(type):
      self.context.append((type, self.partobj))
      self.partobj = []
      return

    def endobj(type1):
      assert self.context
      obj = self.partobj
      (type0, self.partobj) = self.context.pop()
      if type0 != type1:
        raise PSTypeError('type mismatch: %r(%r) != %r(%r)' %
                          (type0, self.partobj, type1, obj))
      return obj

    startobj('o')

    for (pos,t) in PSBaseParser.parse(self):
      if isinstance(t, int) or isinstance(t, float):
        self.push(t)
      elif isinstance(t, str):
        self.push(t)
      elif isinstance(t, PSLiteral):
        self.push(t)
      else:
        c = keyword_name(t)
        if c == '{' or c == '}':
          self.push(t)
        elif c == '[':
          # begin array
          if 2 <= self.debug:
            print >>stderr, 'start array'
          startobj('a')
        elif c == ']':
          # end array
          a = endobj('a')
          if 2 <= self.debug:
            print >>stderr, 'end array: %r' % a
          self.push(a)
        elif c == '<<':
          # begin dictionary
          if 2 <= self.debug:
            print >>stderr, 'start dict'
          startobj('d')
        elif c == '>>':
          # end dictionary
          objs = endobj('d')
          if len(objs) % 2 != 0:
            raise PSTypeError('invalid dictionary construct: %r' % objs)
          d = dict( (literal_name(k), v) for (k,v) in choplist(2, objs) )
          if 2 <= self.debug:
            print >>stderr, 'end dict: %r' % d
          self.push(d)
        elif self.do_token(pos, t):
          break

    return endobj('o')


##  CMapParser
##
class CMapParser(PSStackParser):

  def __init__(self, cmap, fp, debug=0):
    PSStackParser.__init__(self, fp, debug=debug)
    self.cmap = cmap
    self.in_cmap = False
    return

  def do_token(self, pos, token):
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
        (k,v) = self.pop(2)
        self.cmap.attrs[literal_name(k)] = v
      except PSSyntaxError:
        pass
      return
    
    if name == 'usecmap':
      try:
        (cmapname,) = self.pop(1)
        self.cmap.copycmap(CMapDB.get_cmap(literal_name(cmapname)))
      except PSSyntaxError:
        pass
      return
      
    if name == 'begincodespacerange':
      self.popall()
      return
    if name == 'endcodespacerange':
      if 1 <= self.debug:
        print >>stderr, 'codespace: %r' % self.partobj
      self.popall()
      return
    
    if name == 'begincidrange':
      self.popall()
      return
    if name == 'endcidrange':
      for (s,e,cid) in choplist(3, self.partobj):
        assert isinstance(s, str)
        assert isinstance(e, str)
        assert isinstance(cid, int)
        assert len(s) == len(e)
        sprefix = s[:-4]
        eprefix = e[:-4]
        assert sprefix == eprefix
        svar = s[-4:]
        evar = e[-4:]
        s1 = nunpack(svar)
        e1 = nunpack(evar)
        vlen = len(svar)
        assert s1 <= e1
        for i in xrange(e1-s1+1):
          x = sprefix+pack('>L',s1+i)[-vlen:]
          self.cmap.register_code2cid(x, cid+i)
      self.popall()
      return
    
    if name == 'begincidchar':
      self.popall()
      return
    if name == 'endcidchar':
      for (cid,code) in choplist(2, self.partobj):
        assert isinstance(code, str)
        assert isinstance(cid, str)
        self.cmap.register_code2cid(code, nunpack(cid))
      self.popall()
      return
        
    if name == 'beginbfrange':
      self.popall()
      return
    if name == 'endbfrange':
      for (s,e,code) in choplist(3, self.partobj):
        assert isinstance(s, str)
        assert isinstance(e, str)
        assert len(s) == len(e)
        s1 = nunpack(s)
        e1 = nunpack(e)
        assert s1 <= e1
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
      self.popall()
      return
        
    if name == 'beginbfchar':
      self.popall()
      return
    if name == 'endbfchar':
      for (cid,code) in choplist(2, self.partobj):
        assert isinstance(cid, str)
        assert isinstance(code, str)
        self.cmap.register_cid2code(nunpack(cid), code)
      self.popall()
      return
        
    if name == 'beginnotdefrange':
      self.popall()
      return
    if name == 'endnotdefrange':
      if 1 <= self.debug:
        print >>stderr, 'notdefrange: %r' % self.partobj
      self.popall()
      return
    
    return


##  PDFStream type
##
class PDFStream:
  
  def __init__(self, doc, dic, rawdata):
    self.doc = doc
    self.dic = dic
    self.rawdata = rawdata
    self.data = None
    return
  
  def __repr__(self):
    return '<PDFStream: %r>' % (self.dic)

  def decode(self):
    assert self.data == None and self.rawdata != None
    data = self.rawdata
    if self.doc.crypt:
      # func DECRYPT is not implemented yet...
      raise NotImplementedError
      data = DECRYPT(self.doc.crypt, data)
    if 'Filter' not in self.dic:
      self.data = data
      self.rawdata = None
      return
    filters = self.dic['Filter']
    if not isinstance(filters, list):
      filters = [ filters ]
    for f in filters:
      if f == LITERAL_FLATE_DECODE:
        import zlib
        # will get errors if the document is encrypted.
        data = zlib.decompress(data)
        # apply predictors
        params = self.dic.get('DecodeParms', {})
        if 'Predictor' in params:
          pred = int_value(params['Predictor'])
          if pred:
            if pred != 12:
              raise PDFValueError('Unsupported predictor: %r' % pred)
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
      else:
        raise PDFValueError('Invalid filter spec: %r' % f)
    self.data = data
    self.rawdata = None
    return

  def get_data(self):
    if self.data == None:
      self.decode()
    return self.data

  def parse_data(self, inline=False, debug=0):
    return PDFParser(self.doc, StringIO(self.get_data()),
                     inline=inline, debug=debug).parse()
  

##  PDFObjRef
##
class PDFObjRef:
  
  def __init__(self, doc, objid, genno):
    if objid == 0:
      raise PDFValueError('objid cannot be 0.')
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

def resolveall(x):
  '''
  Recursively resolve X and all the internals.
  Make sure there is no indirect reference within the nested object.
  This procedure might be slow. Do not used it unless
  you really need it.
  '''
  while isinstance(x, PDFObjRef):
    x = x.resolve()
  if isinstance(x, list):
    x = [ resolveall(v) for v in x ]
  elif isinstance(x, dict):
    for (k,v) in x.iteritems():
      x[k] = resolveall(v)
  return x

# Type cheking
def literal_name(x):
  x = resolve1(x)
  if not isinstance(x, PSLiteral):
    raise PDFTypeError('literal required: %r' % x)
  return x.name

def keyword_name(x):
  x = resolve1(x)
  if not isinstance(x, PSKeyword):
    raise PDFTypeError('keyword required: %r' % x)
  return x.name

def str_value(x):
  x = resolve1(x)
  if not isinstance(x, str):
    raise PDFTypeError('string required: %r' % x)
  return x

def int_value(x):
  x = resolve1(x)
  if not isinstance(x, int):
    raise PDFTypeError('integer required: %r' % x)
  return x

def float_value(x):
  x = resolve1(x)
  if not isinstance(x, float):
    raise PDFTypeError('float required: %r' % x)
  return x

def num_value(x):
  x = resolve1(x)
  if not (isinstance(x, int) or isinstance(x, float)):
    raise PDFTypeError('int or float required: %r' % x)
  return x

def list_value(x):
  x = resolve1(x)
  if not isinstance(x, list):
    raise PDFTypeError('list required: %r' % x)
  return x

def dict_value(x):
  x = resolve1(x)
  if not isinstance(x, dict):
    raise PDFTypeError('dict required: %r' % x)
  return x

def stream_value(x):
  x = resolve1(x)
  if not isinstance(x, PDFStream):
    raise PDFTypeError('stream required: %r' % x)
  return x


##  PDFPage
##
class PDFPage:
  
  def __init__(self, doc, pageidx, attrs, parent_attrs):
    self.doc = doc
    self.pageid = pageidx
    self.attrs = dict_value(attrs)
    self.parent_attrs = parent_attrs
    self.resources = self.get_attr('Resources')
    self.mediabox = self.get_attr('MediaBox')
    contents = resolve1(self.attrs['Contents'])
    if not isinstance(contents, list):
      contents = [ contents ]
    self.contents = contents
    return

  def __repr__(self):
    return '<PDFPage: Resources=%r, MediaBox=%r>' % (self.resources, self.mediabox)
  
  def get_attr(self, k):
    if k in self.attrs:
      return resolve1(self.attrs[k])
    return self.parent_attrs.get(k)


##  XRefs

##  PDFXRef
##
class PDFXRef:

  def __init__(self, parser):
    while 1:
      line = parser.nextline()
      if not line:
        raise PDFSyntaxError('premature eof: %r' % parser)
      line = line.strip()
      f = line.split(' ')
      if len(f) != 2:
        if line != 'trailer':
          raise PDFSyntaxError('trailer not found: %r: line=%r' % (parser, line))
        break
      (start, nobjs) = map(long, f)
      self.objid0 = start
      self.objid1 = start+nobjs
      self.offsets = []
      for objid in xrange(start, start+nobjs):
        line = parser.nextline()
        f = line.strip().split(' ')
        if len(f) != 3:
          raise PDFSyntaxError('invalid xref format: %r, line=%r' % (parser, line))
        (pos, genno, use) = f
        self.offsets.append((int(genno), long(pos), use))
    # read trailer
    self.trailer = dict_value(parser.parse()[0])
    return

  def getpos(self, objid):
    if objid < self.objid0 or self.objid1 <= objid:
      raise IndexError
    (genno, pos, use) = self.offsets[objid-self.objid0]
    if use != 'n':
      raise PDFValueError('unused objid=%r' % objid)
    return (None, pos)


##  PDFXRefStream
##
class PDFXRefStream:

  def __init__(self, parser):
    (objid, genno, _, stream) = list_value(parser.parse())
    assert stream.dic['Type'] == LITERAL_XREF
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
      raise IndexError
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
class PDFDocument:
  
  def __init__(self, debug=0):
    self.debug = debug
    self.xrefs = []
    self.objs = {}
    self.parsed_objs = {}
    self.crypt = None
    self.root = None
    self.catalog = None
    self.parser = None
    return

  def set_parser(self, parser):
    if self.parser: return
    self.parser = parser
    self.xrefs = list(parser.read_xref())
    for xref in self.xrefs:
      trailer = xref.trailer
      if 'Encrypt' in trailer:
        self.crypt = dict_value(trailer['Encrypt'])
      if 'Root' in trailer:
        self.set_root(dict_value(trailer['Root']))
        break
    else:
      raise PDFValueError('no /Root object!')
    return

  def getobj(self, objid):
    assert self.xrefs
    if objid in self.objs:
      obj = self.objs[objid]
    else:
      for xref in self.xrefs:
        try:
          (strmid, index) = xref.getpos(objid)
          break
        except IndexError:
          pass
      else:
        raise PDFValueError('Cannot locate objid=%r' % objid)
      if strmid:
        stream = stream_value(self.getobj(strmid))
        if stream.dic['Type'] != LITERAL_OBJSTM:
          raise PDFSyntaxError('Not a stream object: %r' % stream)
        if 'N' not in stream.dic:
          raise PDFSyntaxError('N is not defined: %r' % stream)
        if strmid in self.parsed_objs:
          objs = self.parsed_objs[stream]
        else:
          objs = stream.parse_data(self.debug)
          self.parsed_objs[stream] = objs
        obj = objs[stream.dic['N']*2+index]
      else:
        pos0 = self.parser.linepos
        self.parser.seek(index)
        seq = list_value(self.parser.parse())
        if not (len(seq) == 4 and seq[0] == objid and seq[2] == KEYWORD_OBJ):
          raise PDFSyntaxError('invalid stream spec: %r' % seq)
        obj = seq[3]
        self.parser.seek(pos0)
      if 2 <= self.debug:
        print >>stderr, 'register: objid=%r: %r' % (objid, obj)
      self.objs[objid] = obj
    return obj
  
  def get_pages(self, debug=0):
    assert self.xrefs
    def search(obj, parent):
      tree = dict_value(obj)
      if tree['Type'] == LITERAL_PAGES:
        if 1 <= debug:
          print >>stderr, 'Pages: Kids=%r' % tree['Kids']
        for c in tree['Kids']:
          for x in search(c, tree):
            yield x
      elif tree['Type'] == LITERAL_PAGE:
        if 1 <= debug:
          print >>stderr, 'Page: %r' % tree
        yield (tree, parent)
    for (i,(tree,parent)) in enumerate(search(self.catalog['Pages'], self.catalog)):
      yield PDFPage(self, i, tree, parent)
    return 

  def set_root(self, root):
    self.root = root
    self.catalog = dict_value(self.root)
    if self.catalog['Type'] != LITERAL_CATALOG:
      raise PDFValueError('Catalog not found!')
    self.outline = self.catalog.get('Outline')
    return
  

##  PDFParser
##
class PDFParser(PSStackParser):

  def __init__(self, doc, fp, inline=False, debug=0):
    PSStackParser.__init__(self, fp, debug=debug)
    self.inline = inline
    self.doc = doc
    self.doc.set_parser(self)
    return

  def __repr__(self):
    return '<PDFParser: linepos=%d>' % self.linepos

  EOIPAT = re.compile(r'\nEI\W')
  def do_token(self, pos, token):
    name = keyword_name(token)
    if name in ('xref', 'trailer', 'startxref', 'endobj'):
      return True
      
    if name == 'R':
      # reference to indirect object
      try:
        (objid, genno) = self.pop(2)
        (objid, genno) = (int(objid), int(genno))
        obj = PDFObjRef(self.doc, objid, genno)
        self.push(obj)
        if 2 <= self.debug:
          print >>stderr, 'refer obj: %r' % obj
      except PSSyntaxError:
        pass
      
    elif name == 'stream':
      # stream object
      (dic,) = self.pop(1)
      dic = dict_value(dic)
      if 'Length' not in dic:
        raise PDFValueError('/Length is undefined: %r' % dic)
      objlen = int_value(dic['Length'])
      self.seek(pos)
      line = self.nextline()  # 'stream'
      self.fp.seek(pos+len(line))
      data = self.fp.read(objlen)
      self.seek(pos+len(line)+objlen)
      while 1:
        line = self.nextline()
        if not line:
          raise PDFSyntaxError('premature eof, need endstream: linepos=%d, line=%r' %
                               (self.linepos, line))
        if line.strip():
          if not line.startswith('endstream'):
            raise PDFSyntaxError('need endstream: linepos=%d, line=%r' %
                                 (self.linepos, line))
          break
      if 1 <= self.debug:
        print >>stderr, 'Stream: pos=%d, objlen=%d, dic=%r, data=%r...' % \
              (pos, objlen, dic, data[:10])
      obj = PDFStream(self.doc, dic, data)
      self.push(obj)

    elif self.inline and name == 'BI':
      # inline image within a content stream
      self.context.append(('BI', self.partobj))
      self.partobj = []
      
    elif self.inline and name == 'ID':
      objs = self.partobj
      (type0, self.partobj) = self.context.pop()
      if len(objs) % 2 != 0:
        raise PSTypeError('invalid dictionary construct: %r' % objs)
      dic = dict( (literal_name(k), v) for (k,v) in choplist(2, objs) )
      pos += len('ID ')
      self.fp.seek(pos)
      data = self.fp.read(8192) 
      # XXX how do we know the real length other than scanning?
      m = self.EOIPAT.search(data)
      assert m
      objlen = m.start(0)
      obj = PDFStream(self.doc, dic, data[:objlen])
      self.push(obj)
      self.seek(pos+objlen+len('\nEI'))
      self.push(KEYWORD_EI)
      
    else:
      self.push(token)

    return False

  def find_xref(self):
    # find the first xref table
    prev = None
    for line in self.revreadlines():
      line = line.strip()
      if 2 <= self.debug:
        print >>stderr, 'line: %r' % line
      if line == 'startxref': break
      if line:
        prev = line
    else:
      raise PDFSyntaxError('startxref not found!')
    if 1 <= self.debug:
      print >>stderr, 'xref found: pos=%r' % prev
    self.seek(long(prev))
    return

  # read xref tables and trailers
  def read_xref(self):
    self.find_xref()
    while 1:
      # read xref table
      pos0 = self.linepos
      line = self.nextline()
      if 2 <= self.debug:
        print >>stderr, 'line: %r' % line
      if line[0].isdigit():
        # XRefStream: PDF-1.5
        self.seek(pos0)
        xref = PDFXRefStream(self)
      elif line.strip() != 'xref':
        raise PDFSyntaxError('xref not found: linepos=%d, line=%r' %
                             (self.linepos, line))
      else:
        xref = PDFXRef(self)
      yield xref
      trailer = xref.trailer
      if 1 <= self.debug:
        print >>stderr, 'trailer: %r' % trailer
      if 'XRefStm' in trailer:
        self.seek(int_value(trailer['XRefStm']))
      if 'Prev' in trailer:
        # find previous xref
        pos0 = int_value(trailer['Prev'])
        self.seek(pos0)
        if 1 <= self.debug:
          print >>stderr, 'prev trailer: pos=%d' % pos0
      else:
        break
    return


##  Fonts
##

# PDFFont
class PDFFont:
  
  def __init__(self, fontid, descriptor, widths, default_width=None):
    self.fontid = fontid
    self.descriptor = descriptor
    self.widths = widths
    self.fontname = descriptor['FontName']
    if isinstance(self.fontname, PSLiteral):
      self.fontname = literal_name(self.fontname)
    self.ascent = descriptor['Ascent']
    self.descent = descriptor['Descent']
    self.default_width = default_width or descriptor.get('MissingWidth', 0)
    self.leading = descriptor.get('Leading', 0)
    self.bbox = descriptor['FontBBox']
    return

  def __repr__(self):
    return '<PDFFont: fontid=%r>' % (self.fontid,)

  def is_vertical(self):
    return False
  
  def decode(self, bytes):
    return map(ord, bytes)

  def char_width(self, cid):
    return self.widths.get(cid, self.default_width)

  def char_disp(self, cid):
    return 0
  
  def string_width(self, s):
    return sum( self.char_width(cid) for cid in self.decode(s) )
  

# PDFSimpleFont
class PDFSimpleFont(PDFFont):
  
  def __init__(self, fontid, descriptor, widths, spec):
    # Font encoding is specified either by a name of
    # built-in encoding or a dictionary that describes
    # the differences.
    if 'Encoding' in spec:
      encoding = resolve1(spec['Encoding'])
    else:
      encoding = LITERAL_STANDARD_ENCODING
    if isinstance(encoding, dict):
      name = literal_name(encoding.get('BaseEncoding', LITERAL_STANDARD_ENCODING))
      diff = encoding.get('Differences', None)
      self.encoding = EncodingDB.get_encoding(name, diff)
    else:
      self.encoding = EncodingDB.get_encoding(literal_name(encoding))
    self.ucs2_cmap = None
    if 'ToUnicode' in spec:
      strm = stream_value(spec['ToUnicode'])
      self.ucs2_cmap = CMap()
      CMapParser(self.ucs2_cmap, StringIO(strm.get_data())).parse()
    PDFFont.__init__(self, fontid, descriptor, widths)
    return

  def to_unicode(self, cid):
    if not self.ucs2_cmap:
      try:
        return self.encoding[cid]
      except KeyError:
        raise PDFUnicodeNotDefined(None, cid)
    code = self.ucs2_cmap.tocode(cid)
    if not code:
      raise PDFUnicodeNotDefined(None, cid)
    chars = unpack('>%dH' % (len(code)/2), code)
    return ''.join( unichr(c) for c in chars )


# PDFType1Font
class PDFType1Font(PDFSimpleFont):
  
  def __init__(self, fontid, spec):
    if 'BaseFont' not in spec:
      raise PDFFontError('BaseFont is missing')
    self.basefont = literal_name(spec['BaseFont'])
    try:
      (descriptor, widths) = FontMetricsDB.get_metrics(self.basefont)
    except KeyError:
      try:
        descriptor = dict_value(spec['FontDescriptor'])
        firstchar = int_value(spec['FirstChar'])
        lastchar = int_value(spec['LastChar'])
        widths = dict( (i+firstchar,w) for (i,w)
                       in enumerate(list_value(spec['Widths'])) )
      except KeyError, k:
        raise PDFFontError('%s is missing' % k)
    PDFSimpleFont.__init__(self, fontid, descriptor, widths, spec)
    return

# PDFTrueTypeFont
class PDFTrueTypeFont(PDFType1Font):
  pass

# PDFType3Font
class PDFType3Font(PDFSimpleFont):
  def __init__(self, fontid, spec):
    try:
      firstchar = int_value(spec['FirstChar'])
      lastchar = int_value(spec['LastChar'])
      widths = dict( (i+firstchar,w) for (i,w)
                     in enumerate(list_value(spec['Widths'])) )
    except KeyError, k:
      raise PDFFontError('%s is missing' % k)
    if 'FontDescriptor' in spec:
      descriptor = dict_value(spec['FontDescriptor'])
    else:
      descriptor = {'FontName':fontid, 'Ascent':0, 'Descent':0,
                    'FontBBox':spec['FontBBox']}
    PDFSimpleFont.__init__(self, fontid, descriptor, widths, spec)
    return

# PDFCIDFont

##  TrueTypeFont
##
class TrueTypeFont:

  class CMapNotFound(Exception): pass
  
  def __init__(self, name, fp):
    self.name = name
    self.fp = fp
    self.tables = {}
    fonttype = fp.read(4)
    (ntables, _1, _2, _3) = unpack('>HHHH', fp.read(8))
    for i in xrange(ntables):
      (name, tsum, offset, length) = unpack('>4sLLL', fp.read(16))
      self.tables[name] = (offset, length)
    return

  def create_cmap(self):
    if 'cmap' not in self.tables: raise TrueTypeFont.CMapNotFound
    (base_offset, length) = self.tables['cmap']
    fp = self.fp
    fp.seek(base_offset)
    (version, nsubtables) = unpack('>HH', fp.read(4))
    subtables = []
    for i in xrange(nsubtables):
      subtables.append(unpack('>HHL', fp.read(8)))
    char2gid = {}
    # Only supports subtable type 0, 2 and 4.
    for (_1, _2, st_offset) in subtables:
      fp.seek(base_offset+st_offset)
      (fmttype, fmtlen, fmtlang) = unpack('>HHH', fp.read(6))
      if fmttype == 0:
        char2gid.update(enumerate(unpack('>256B', fp.read(256))))
      elif fmttype == 2:
        subheaderkeys = unpack('>256H', fp.read(512))
        firstbytes = [0]*8192
        for (i,k) in enumerate(subheaderkeys):
          firstbytes[k/8] = i
        nhdrs = max(subheaderkeys)/8 + 1
        hdrs = []
        for i in xrange(nhdrs):
          (firstcode,entcount,delta,offset) = unpack('>HHhH', fp.read(8))
          hdrs.append((i,firstcode,entcount,delta,fp.tell()-2+offset))
        for (i,firstcode,entcount,delta,pos) in hdrs:
          if not entcount: continue
          first = firstcode + (firstbytes[i] << 8)
          fp.seek(pos)
          for c in xrange(entcount):
            gid = unpack('>H', fp.read(2))
            if gid:
              gid += delta
            char2gid[first+c] = gid
      elif fmttype == 4:
        (segcount, _1, _2, _3) = unpack('>HHHH', fp.read(8))
        segcount /= 2
        ecs = unpack('>%dH' % segcount, fp.read(2*segcount))
        fp.read(2)
        scs = unpack('>%dH' % segcount, fp.read(2*segcount))
        idds = unpack('>%dh' % segcount, fp.read(2*segcount))
        pos = fp.tell()
        idrs = unpack('>%dH' % segcount, fp.read(2*segcount))
        for (ec,sc,idd,idr) in zip(ecs, scs, idds, idrs):
          if idr:
            fp.seek(pos+idr)
            for c in xrange(sc, ec+1):
              char2gid[c] = (unpack('>H', fp.read(2))[0] + idd) & 0xffff
          else:
            for c in xrange(sc, ec+1):
              char2gid[c] = (c + idd) & 0xffff
    gid2char = dict( (gid, pack('>H', char))
                     for (char,gid) in char2gid.iteritems() )
    cmapname = 'Adobe-Identity-UCS-%s' % self.name
    return CMap(cmapname).update(char2gid, gid2char)

class PDFCIDFont(PDFFont):
  
  def __init__(self, fontid, spec):
    if 'BaseFont' not in spec:
      raise PDFFontError('BaseFont is missing')
    try:
      self.cidsysteminfo = dict_value(spec['CIDSystemInfo'])
      self.cidcoding = '%s-%s' % (self.cidsysteminfo['Registry'],
                                  self.cidsysteminfo['Ordering'])
    except KeyError:
      raise PDFFontError('CIDSystemInfo not properly defined.')
    self.basefont = literal_name(spec['BaseFont'])
    self.cmap = CMapDB.get_cmap(literal_name(spec['Encoding']))
    descriptor = dict_value(spec['FontDescriptor'])
    ttf = None
    if 'FontFile2' in descriptor:
      self.fontfile = stream_value(descriptor.get('FontFile2'))
      ttf = TrueTypeFont(self.basefont,
                         StringIO(self.fontfile.get_data()))
    self.ucs2_cmap = None
    if 'ToUnicode' in spec:
      strm = stream_value(spec['ToUnicode'])
      self.ucs2_cmap = CMap()
      CMapParser(self.ucs2_cmap, StringIO(strm.get_data())).parse()
    elif self.cidcoding == 'Adobe-Identity':
      if ttf:
        try:
          self.ucs2_cmap = ttf.create_cmap()
        except TrueTypeFont.CMapNotFound:
          pass
    else:
      self.ucs2_cmap = CMapDB.get_cmap('%s-UCS2' % self.cidcoding)
    def get_width(seq):
      dic = {}
      char1 = char2 = None
      for v in seq:
        if char1 == None:
          char1 = v
        elif char2 == None and isinstance(v, int):
          char2 = v
        else:
          if char2 == None:
            for (i,w) in enumerate(v):
              dic[char1+i] = w
          else:
            for i in xrange(char1, char2+1):
              dic[i] = v
          char1 = char2 = None
      return dic
    self.vertical = self.cmap.is_vertical()
    if self.vertical:
      # writing mode: vertical
      dic = get_width(list_value(spec.get('W2', [])))
      widths = dict( (cid,w) for (cid,(d,w)) in dic.iteritems() )
      self.disps = dict( (cid,d) for (cid,(d,w)) in dic.iteritems() )
      (d,w) = spec.get('DW2', [880, -1000])
      default_width = w
      self.default_disp = d
    else:
      # writing mode: horizontal
      widths = get_width(list_value(spec.get('W', [])))
      self.disps = {}
      default_width = spec.get('DW', 1000)
      self.default_disp = 0
    PDFFont.__init__(self, fontid, descriptor, widths, default_width)
    return

  def is_vertical(self):
    return self.vertical
  
  def decode(self, bytes):
    return self.cmap.decode(bytes)

  def char_disp(self, cid):
    return self.disps.get(cid, self.default_disp)

  def to_unicode(self, cid):
    if not self.ucs2_cmap:
      raise PDFUnicodeNotDefined(self.cidcoding, cid)
    code = self.ucs2_cmap.tocode(cid)
    if not code:
      raise PDFUnicodeNotDefined(self.cidcoding, cid)
    chars = unpack('>%dH' % (len(code)/2), code)
    return ''.join( unichr(c) for c in chars )


##  Resource Manager
##
class PDFResourceManager:

  '''
  ResourceManager facilitates reuse of shared resources
  such as fonts, images and cmaps so that large objects are not
  allocated multiple times.
  '''
  
  def __init__(self, debug=0):
    self.debug = debug
    self.fonts = {}
    return

  def get_procset(self, procs):
    for proc in procs:
      if proc == LITERAL_PDF:
        pass
      elif proc == LITERAL_TEXT:
        pass
      else:
        #raise PDFResourceError('ProcSet %r is not supported.' % proc)
        pass
    return
  
  def get_cmap(self, name):
    return CMapDB.get_cmap(name)

  def get_font(self, fontid, spec):
    if fontid in self.fonts:
      font = self.fonts[fontid]
    else:
      spec = dict_value(spec)
      assert spec['Type'] == LITERAL_FONT
      # Create a Font object.
      if 'Subtype' not in spec:
        raise PDFFontError('Font Subtype is not specified.')
      subtype = literal_name(spec['Subtype'])
      if subtype in ('Type1', 'MMType1'):
        # Type1 Font
        font = PDFType1Font(fontid, spec)
      elif subtype == 'TrueType':
        # TrueType Font
        font = PDFTrueTypeFont(fontid, spec)
      elif subtype == 'Type3':
        # Type3 Font
        font = PDFType3Font(fontid, spec)
      elif subtype in ('CIDFontType0', 'CIDFontType2'):
        # CID Font
        font = PDFCIDFont(fontid, spec)
      elif subtype == 'Type0':
        # Type0 Font
        dfonts = list_value(spec['DescendantFonts'])
        assert len(dfonts) == 1
        subspec = dict_value(dfonts[0]).copy()
        for k in ('Encoding', 'ToUnicode'):
          if k in spec:
            subspec[k] = resolve1(spec[k])
        font = self.get_font(fontid, subspec)
      else:
        raise PDFFontError('Invalid Font: %r' % spec)
      self.fonts[fontid] = font
    return font


##  Interpreter
##
class PDFPageInterpreter:
  
  class TextState:
    def __init__(self):
      self.font = None
      self.fontsize = 0
      self.charspace = 0
      self.wordspace = 0
      self.scaling = 100
      self.leading = 0
      self.render = 0
      self.rise = 0
      self.reset()
      return
    def __repr__(self):
      return ('<TextState: font=%r, fontsize=%r, matrix=%r,'
              ' charspace=%r, wordspace=%r, scaling=%r, leading=%r,'
              ' render=%r, rise=%r>' %
              (self.font, self.fontsize, self.matrix,
               self.charspace, self.wordspace, self.scaling, self.leading,
               self.render, self.rise))
    def reset(self):
      self.matrix = (1, 0, 0, 1, 0, 0)
      self.linematrix = (0, 0)
      return

  def __init__(self, rsrc, device, debug=0):
    self.rsrc = rsrc
    self.device = device
    self.debug = debug
    return

  def initpage(self, ctm):
    self.fontmap = {}
    self.xobjmap = {}
    self.csmap = {}
    # gstack: stack for graphical states.
    self.gstack = []
    self.ctm = ctm
    self.device.set_ctm(self.ctm)
    self.textstate = PDFPageInterpreter.TextState()
    # argstack: stack for command arguments.
    self.argstack = []
    # set some global states.
    self.scs = None
    self.ncs = None
    return

  def push(self, obj):
    self.argstack.append(obj)
    return

  def pop(self, n):
    x = self.argstack[-n:]
    self.argstack = self.argstack[:-n]
    return x

  def get_current_state(self):
    return (self.ctm, self.textstate)
  
  def set_current_state(self, state):
    (self.ctm, self.textstate) = state
    self.device.set_ctm(self.ctm)
    return

  # gsave
  def do_q(self):
    self.gstack.append(self.get_current_state())
    return
  # grestore
  def do_Q(self):
    if self.gstack:
      self.set_current_state(self.gstack.pop())
    return
  
  # concat-matrix
  def do_cm(self, a1, b1, c1, d1, e1, f1):
    self.ctm = mult_matrix((a1,b1,c1,d1,e1,f1), self.ctm)
    self.device.set_ctm(self.ctm)
    return
  
  # setlinewidth
  def do_w(self, width): return
  # setlinecap
  def do_J(self, cap): return
  # setlinejoin
  def do_j(self, join): return
  # setmiterlimit
  def do_M(self, limit): return
  # setdash
  def do_d(self, dash, phase): return
  # setintent
  def do_ri(self, intent): return
  # setflatness
  def do_i(self, flatness): return
  # savedict
  def do_gs(self, name): return
  
  # moveto
  def do_m(self, x, y): return
  # lineto
  def do_l(self, x, y): return
  # curveto
  def do_c(self, x1, y1, x2, y2, x3, y3): return
  # urveto
  def do_v(self, x2, y2, x3, y3): return
  # rveto
  def do_y(self, x1, y1, x3, y3): return
  # closepath
  def do_h(self): return
  # rectangle
  def do_re(self, x, y, w, h): return
  
  # stroke
  def do_S(self): return
  # close-and-stroke
  def do_s(self): return
  # fill
  def do_f(self): return
  # fill (obsolete)
  do_F = do_f
  # fill-even-odd
  def do_f_a(self): return
  # fill-and-stroke
  def do_B(self): return
  # fill-and-stroke-even-odd
  def do_B_a(self): return
  # close-fill-and-stroke
  def do_b(self): return
  # close-fill-and-stroke-even-odd
  def do_b_a(self): return
  # close-only
  def do_n(self): return
  # clip
  def do_W(self): return
  # clip-even-odd
  def do_W_a(self): return
  
  # setcolorspace-stroking
  def do_CS(self, name):
    self.scs = self.csmap.get(literal_name(name), None)
    return
  # setcolorspace-non-strokine
  def do_cs(self, name):
    self.ncs = self.csmap.get(literal_name(name), None)
    return
  # setgray-stroking
  def do_G(self, gray):
    self.do_CS(LITERAL_DEVICE_GRAY)
    return
  # setgray-non-stroking
  def do_g(self, gray):
    self.do_cs(LITERAL_DEVICE_GRAY)
    return
  # setrgb-stroking
  def do_RG(self, r, g, b):
    self.do_CS(LITERAL_DEVICE_RGB)
    return
  # setrgb-non-stroking
  def do_rg(self, r, g, b):
    self.do_cs(LITERAL_DEVICE_RGB)
    return
  # setcmyk-stroking
  def do_K(self, c, m, y, k):
    self.do_CS(LITERAL_DEVICE_CMYK)
    return
  # setcmyk-non-stroking
  def do_k(self, c, m, y, k):
    self.do_cs(LITERAL_DEVICE_CMYK)
    return

  # setcolor
  def do_SCN(self):
    n = cs_params(self.scs)
    self.pop(n)
    return
  def do_scn(self):
    n = cs_params(self.ncs)
    self.pop(n)
    return
  def do_SC(self):
    self.do_SCN()
    return
  def do_sc(self):
    self.do_scn()
    return
    
  # sharing-name
  def do_sh(self, name): return
  
  # begin-text
  def do_BT(self):
    self.textstate.reset()
    return
  # end-text
  def do_ET(self):
    return

  # begin-compat
  def do_BX(self): return
  # end-compat
  def do_EX(self): return

  # marked content operators
  def do_MP(self, tag): return
  def do_DP(self, tag, props): return
  def do_BMC(self, tag): return
  def do_BDC(self, tag, props): return
  def do_EMC(self): return

  # setcharspace
  def do_Tc(self, space):
    self.textstate.charspace = space
    return
  # setwordspace
  def do_Tw(self, space):
    self.textstate.wordspace = space
    return
  # textscale
  def do_Tz(self, scale):
    self.textstate.scaling = scale
    return
  # setleading
  def do_TL(self, leading):
    self.textstate.leading = leading
    return
  # selectfont
  def do_Tf(self, fontid, fontsize):
    try:
      self.textstate.font = self.fontmap[literal_name(fontid)]
    except KeyError:
      raise PDFInterpreterError('Undefined font id: %r' % fontid)
    self.textstate.fontsize = fontsize
    return
  # setrendering
  def do_Tr(self, render):
    self.textstate.render = render
    return
  # settextrise
  def do_Ts(self, rise):
    self.textstate.rise = rise
    return

  # text-move
  def do_Td(self, tx, ty):
    (a,b,c,d,e,f) = self.textstate.matrix
    self.textstate.matrix = (a,b,c,d,e+tx,f+ty)
    self.textstate.linematrix = (0, 0)
    return
  # text-move
  def do_TD(self, tx, ty):
    (a,b,c,d,e,f) = self.textstate.matrix
    self.textstate.matrix = (a,b,c,d,e+tx,f+ty)
    self.textstate.leading = -ty
    self.textstate.linematrix = (0, 0)
    return
  # textmatrix
  def do_Tm(self, a,b,c,d,e,f):
    self.textstate.matrix = (a,b,c,d,e,f)
    self.textstate.linematrix = (0, 0)
    return
  # nextline
  def do_T_a(self):
    (a,b,c,d,e,f) = self.textstate.matrix
    self.textstate.matrix = (a,b,c,d,e,f+self.textstate.leading)
    self.textstate.linematrix = (0, 0)
    return
  
  # show-pos
  def do_TJ(self, seq):
    textstate = self.textstate
    font = textstate.font
    (a,b,c,d,e,f) = textstate.matrix
    (lx,ly) = textstate.linematrix
    s = ''.join( x for x in seq if isinstance(x, str) )
    n = sum( x for x in seq if not isinstance(x, str) )
    w = ((font.string_width(s)-n)/1000.0 * textstate.fontsize +
         len(s) * textstate.charspace +
         s.count(' ')*textstate.wordspace) * textstate.scaling / 100.0
    self.device.render_string(textstate, (a,b,c,d,e+lx,f+ly), w, seq)
    if font.is_vertical():
      ly += w
    else:
      lx += w
    textstate.linematrix = (lx,ly)
    return
  # show
  def do_Tj(self, s):
    self.do_TJ([s])
    return
  # quote
  def do__q(self, s):
    self.do_T_a()
    self.do_TJ([s])
    return
  # doublequote
  def do__w(self, aw, ac, s):
    self.do_Tw(aw)
    self.do_Tc(ac)
    self.do_TJ([s])
    return

  # inline image
  def do_BI(self): # never called
    return
  def do_ID(self): # never called
    return
  def do_EI(self, obj):
    return

  # invoke an XObject
  def do_Do(self, xobjid):
    xobjid = literal_name(xobjid)
    try:
      xobj = stream_value(self.xobjmap[xobjid])
    except KeyError:
      raise PDFInterpreterError('Undefined xobject id: %r' % xobjid)
    if xobj.dic['Subtype'] == LITERAL_FORM:
      if 1 <= self.debug:
        print >>stderr, 'Processing xobj: %r' % xobj
      interpreter = PDFPageInterpreter(self.rsrc, self.device)
      interpreter.render_contents(xobjid, xobj.dic['Resources'], [xobj], xobj.dic['Matrix'])
    return

  def process_page(self, page):
    if 1 <= self.debug:
      print >>stderr, 'Processing page: %r' % page
    self.render_contents('page-%d' % page.pageid, page.resources, page.contents)
    return

  def render_contents(self, contid, resources, contents, ctm=(1, 0, 0, 1, 0, 0)):
    self.initpage(ctm)
    self.device.begin_block(contid)
    # Handle resource declarations.
    for (k,v) in resources.iteritems():
      if 1 <= self.debug:
        print >>stderr, 'Resource: %r: %r' % (k,v)
      if k == 'Font':
        for (fontid,fontrsrc) in dict_value(v).iteritems():
          self.fontmap[fontid] = self.rsrc.get_font(fontid, fontrsrc)
      elif k == 'ColorSpace':
        for (csid,csspec) in dict_value(v).iteritems():
          self.csmap[csid] = list_value(csspec)
      elif k == 'ProcSet':
        self.rsrc.get_procset(list_value(v))
      elif k == 'XObject':
        for (xobjid,xobjstrm) in dict_value(v).iteritems():
          self.xobjmap[xobjid] = xobjstrm
    for stream in contents:
      self.execute(stream_value(stream))
    self.device.end_block()
    return
  
  def execute(self, stream):
    for obj in stream.parse_data(inline=True, debug=self.debug):
      if isinstance(obj, PSKeyword):
        name = 'do_%s' % obj.name.replace('*','_a').replace('"','_w').replace("'",'_q')
        if hasattr(self, name):
          func = getattr(self, name)
          nargs = func.func_code.co_argcount-1
          if nargs:
            args = self.pop(nargs)
            if 1 <= self.debug:
              print >>stderr, 'exec: %s %r' % (obj.name, args)
            if len(args) == nargs:
              func(*args)
          else:
            if 1 <= self.debug:
              print >>stderr, 'exec: %s' % (obj.name)
            func()
        else:
          raise PDFInterpreterError('unknown operator: %r' % obj.name)
      else:
        self.push(obj)
    return


##  PDFDevice
##
class PDFDevice:
  
  def __init__(self, rsrc):
    self.rsrc = rsrc
    self.ctm = None
    return
  
  def __repr__(self):
    return '<PDFDevice>'

  def set_ctm(self, ctm):
    self.ctm = ctm
    return

  def begin_block(self, name):
    return
  def end_block(self):
    return
  
  def render_string(self, textstate, textmatrix, size, seq):
    raise NotImplementedError


##  TextConverter
##
class TextConverter(PDFDevice):

  def __init__(self, rsrc, codec, outfp=sys.stdout):
    PDFDevice.__init__(self, rsrc)
    self.outfp = outfp
    self.codec = codec
    return
  
  def begin_block(self, name):
    self.outfp.write('<block name="%s">\n' % name)
    return
  def end_block(self):
    self.outfp.write('</block>\n')
    return

  def render_string(self, textstate, textmatrix, size, seq):
    font = textstate.font
    spwidth = int(-font.char_width(32) * 0.6) # space width
    buf = ''
    for x in seq:
      if isinstance(x, int) or isinstance(x, float):
        if not font.is_vertical() and x <= spwidth:
          buf += ' '
      else:
        chars = font.decode(x)
        for cid in chars:
          try:
            char = font.to_unicode(cid)
          except PDFUnicodeNotDefined, e:
            (cidcoding, cid) = e.args
            char = u'[%s:%d]' % (cidcoding, cid)
          buf += char
    (a,b,c,d,tx,ty) = mult_matrix(textmatrix, self.ctm)
    skewed = (b != 0 or c != 0)
    if font.is_vertical():
      size = -size
      tag = 'vtext'
    else:
      tag = 'htext'
    if skewed:
      tag += ' skewed'
    s = buf.encode(self.codec, 'xmlcharrefreplace')
    (w,fs) = apply_matrix((a,b,c,d,0,0), (size,textstate.fontsize))
    def f(x): return '%.03f' % x
    self.outfp.write('<%s font="%s" size="%s" x="%s" y="%s" w="%s">%s</%s>\n' %
                     (tag, font.fontname, f(fs), f(tx), f(ty), f(w), s, tag))
    return


# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-v] [-c codec] [-p pages] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dvp:c:')
  except getopt.GetoptError:
    return usage()
  if not args: return usage()
  (debug, verbose) = (0, 0)
  cmapdir = 'CMap'
  cdbcmapdir = 'CDBCMap'
  codec = 'ascii'
  pages = set()
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-v': verbose += 1
    elif k == '-p': pages.add(int(v))
    elif k == '-c': codec = v
  #
  CMapDB.initialize(cmapdir, cdbcmapdir, debug=debug)
  rsrc = PDFResourceManager(debug=debug)
  device = TextConverter(rsrc, codec)
  for fname in args:
    doc = PDFDocument(debug=debug)
    fp = file(fname)
    parser = PDFParser(doc, fp, debug=debug)
    interpreter = PDFPageInterpreter(rsrc, device, debug=debug)
    for (i,page) in enumerate(doc.get_pages(debug=debug)):
      if pages and (i not in pages): continue
      interpreter.process_page(page)
    fp.close()
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
