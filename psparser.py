#!/usr/bin/env python
import sys, re
stderr = sys.stderr
from utils import choplist


##  PS Exceptions
##
class PSException(Exception): pass
class PSSyntaxError(PSException): pass
class PSTypeError(PSException): pass
class PSValueError(PSException): pass


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


def literal_name(x):
  if not isinstance(x, PSLiteral):
    raise PSTypeError('literal required: %r' % x)
  return x.name

def keyword_name(x):
  if not isinstance(x, PSKeyword):
    raise PSTypeError('keyword required: %r' % x)
  return x.name


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
