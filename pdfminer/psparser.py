#!/usr/bin/env python
import sys, re
stderr = sys.stderr
from pdfminer.utils import choplist

STRICT = 0


##  PS Exceptions
##
class PSException(Exception): pass
class PSEOF(PSException): pass
class PSSyntaxError(PSException): pass
class PSTypeError(PSException): pass
class PSValueError(PSException): pass


##  Basic PostScript Types
##

##  PSObject
##
##  Base class for all PS or PDF-related data types.
##
class PSObject(object): pass


##  PSLiteral
##
##  Postscript literals are used as identifiers, such as
##  variable names, property names and dictionary keys.
##  Literals are case sensitive and denoted by a preceding
##  slash sign (e.g. "/Name")
##
##  Note: Never create an instance of PSLiteral by hand.
##  Always use PSLiteralTable.intern().
##
class PSLiteral(PSObject):
  
  def __init__(self, name):
    self.name = name
    return
  
  def __repr__(self):
    return '/%s' % self.name


##  PSKeyword
##
##  Note: Never create an instance of PSLiteral by hand.
##  Always use PSKeywordTable.intern().
##
class PSKeyword(PSObject):
  
  def __init__(self, name):
    self.name = name
    return
  
  def __repr__(self):
    return self.name


##  PSSymbolTable
##
##  A dictionary-like object that is used for
##  storing PSLiteral/PSKeyword objects so that
##  an object that has the same name can never be defined
##  twice and it is always assured that the same name is
##  referred to as the same PSLiteral/PSKeyword object.
##
class PSSymbolTable(object):
  
  def __init__(self, klass):
    self.dic = {}
    self.klass = klass
    return
  
  def intern(self, name):
    if name in self.dic:
      lit = self.dic[name]
    else:
      lit = self.klass(name)
      self.dic[name] = lit
    return lit

PSLiteralTable = PSSymbolTable(PSLiteral)
PSKeywordTable = PSSymbolTable(PSKeyword)
LIT = PSLiteralTable.intern
KWD = PSKeywordTable.intern
KEYWORD_BRACE_BEGIN = KWD('{')
KEYWORD_BRACE_END = KWD('}')
KEYWORD_ARRAY_BEGIN = KWD('[')
KEYWORD_ARRAY_END = KWD(']')
KEYWORD_DICT_BEGIN = KWD('<<')
KEYWORD_DICT_END = KWD('>>')


def literal_name(x):
  if not isinstance(x, PSLiteral):
    if STRICT:
      raise PSTypeError('Literal required: %r' % x)
    else:
      return str(x)
  return x.name

def keyword_name(x):
  if not isinstance(x, PSKeyword):
    if STRICT:
      raise PSTypeError('Keyword required: %r' % x)
    else:
      return str(x)
  return x.name


##  PSBaseParser
##
EOL = re.compile(r'[\r\n]')
SPC = re.compile(r'\s')
NONSPC = re.compile(r'\S')
HEX = re.compile(r'[0-9a-fA-F]')
END_LITERAL = re.compile(r'[#/%\[\]()<>{}\s]')
END_HEX_STRING = re.compile(r'[^\s0-9a-fA-F]')
HEX_PAIR = re.compile(r'[0-9a-fA-F]{2}|.')
END_NUMBER = re.compile(r'[^0-9]')
END_KEYWORD = re.compile(r'[#/%\[\]()<>{}\s]')
END_STRING = re.compile(r'[()\134]')
OCT_STRING = re.compile(r'[0-7]')
ESC_STRING = { 'b':8, 't':9, 'n':10, 'f':12, 'r':13, '(':40, ')':41, '\\':92 }
class PSBaseParser(object):

  '''
  Most basic PostScript parser that performs only tokenization.
  '''
  BUFSIZ = 4096

  debug = 0
  
  def __init__(self, fp):
    self.fp = fp
    self.seek(0)
    return

  def __repr__(self):
    return '<PSBaseParser: %r, bufpos=%d>' % (self.fp, self.bufpos)

  def flush(self):
    return
  
  def close(self):
    self.flush()
    return
  
  def tell(self):
    return self.bufpos+self.charpos

  def poll(self, pos=None, n=80):
    pos0 = self.fp.tell()
    if not pos:
      pos = self.bufpos+self.charpos
    self.fp.seek(pos)
    print >>stderr, 'poll(%d): %r' % (pos, self.fp.read(n))
    self.fp.seek(pos0)
    return

  def seek(self, pos):
    '''
    Seeks the parser to the given position.
    '''
    if 2 <= self.debug:
      print >>stderr, 'seek: %r' % pos
    self.fp.seek(pos)
    # reset the status for nextline()
    self.bufpos = pos
    self.buf = ''
    self.charpos = 0
    # reset the status for nexttoken()
    self._parse1 = self._parse_main
    self._curtoken = ''
    self._curtokenpos = 0
    self._tokens = []
    return

  def fillbuf(self):
    if self.charpos < len(self.buf): return
    # fetch next chunk.
    self.bufpos = self.fp.tell()
    self.buf = self.fp.read(self.BUFSIZ)
    if not self.buf:
      raise PSEOF('Unexpected EOF')
    self.charpos = 0
    return
  
  def nextline(self):
    '''
    Fetches a next line that ends either with \\r or \\n.
    '''
    linebuf = ''
    linepos = self.bufpos + self.charpos
    eol = False
    while 1:
      self.fillbuf()
      if eol:
        c = self.buf[self.charpos]
        # handle '\r\n'
        if c == '\n':
          linebuf += c
          self.charpos += 1
        break
      m = EOL.search(self.buf, self.charpos)
      if m:
        linebuf += self.buf[self.charpos:m.end(0)]
        self.charpos = m.end(0)
        if linebuf[-1] == '\r':
          eol = True
        else:
          break
      else:
        linebuf += self.buf[self.charpos:]
        self.charpos = len(self.buf)
    if 2 <= self.debug:
      print >>stderr, 'nextline: %r' % ((linepos, linebuf),)
    return (linepos, linebuf)

  def revreadlines(self):
    '''
    Fetches a next line backword. This is used to locate
    the trailers at the end of a file.
    '''
    self.fp.seek(0, 2)
    pos = self.fp.tell()
    buf = ''
    while 0 < pos:
      pos = max(0, pos-self.BUFSIZ)
      self.fp.seek(pos)
      s = self.fp.read(self.BUFSIZ)
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

  def _parse_main(self, s, i):
    m = NONSPC.search(s, i)
    if not m:
      return (self._parse_main, len(s))
    j = m.start(0)
    c = s[j]
    self._curtokenpos = self.bufpos+j
    if c == '%':
      self._curtoken = '%'
      return (self._parse_comment, j+1)
    elif c == '/':
      self._curtoken = ''
      return (self._parse_literal, j+1)
    elif c in '-+' or c.isdigit():
      self._curtoken = c
      return (self._parse_number, j+1)
    elif c == '.':
      self._curtoken = c
      return (self._parse_float, j+1)
    elif c.isalpha():
      self._curtoken = c
      return (self._parse_keyword, j+1)
    elif c == '(':
      self._curtoken = ''
      self.paren = 1
      return (self._parse_string, j+1)
    elif c == '<':
      self._curtoken = ''
      return (self._parse_wopen, j+1)
    elif c == '>':
      self._curtoken = ''
      return (self._parse_wclose, j+1)
    else:
      self._add_token(KWD(c))
      return (self._parse_main, j+1)
              
  def _add_token(self, obj):
    self._tokens.append((self._curtokenpos, obj))
    return
  
  def _parse_comment(self, s, i):
    m = EOL.search(s, i)
    if not m:
      self._curtoken += s[i:]
      return (self._parse_comment, len(s))
    j = m.start(0)
    self._curtoken += s[i:j]
    # We ignore comments.
    #self._tokens.append(self._curtoken)
    return (self._parse_main, j)
  
  def _parse_literal(self, s, i):
    m = END_LITERAL.search(s, i)
    if not m:
      self._curtoken += s[i:]
      return (self._parse_literal, len(s))
    j = m.start(0)
    self._curtoken += s[i:j]
    c = s[j]
    if c == '#':
      self.hex = ''
      return (self._parse_literal_hex, j+1)
    self._add_token(LIT(self._curtoken))
    return (self._parse_main, j)
  
  def _parse_literal_hex(self, s, i):
    c = s[i]
    if HEX.match(c) and len(self.hex) < 2:
      self.hex += c
      return (self._parse_literal_hex, i+1)
    if self.hex:
      self._curtoken += chr(int(self.hex, 16))
    return (self._parse_literal, i)

  def _parse_number(self, s, i):
    m = END_NUMBER.search(s, i)
    if not m:
      self._curtoken += s[i:]
      return (self._parse_number, len(s))
    j = m.start(0)
    self._curtoken += s[i:j]
    c = s[j]
    if c == '.':
      self._curtoken += c
      return (self._parse_float, j+1)
    try:
      self._add_token(int(self._curtoken))
    except ValueError:
      pass
    return (self._parse_main, j)
  
  def _parse_float(self, s, i):
    m = END_NUMBER.search(s, i)
    if not m:
      self._curtoken += s[i:]
      return (self._parse_float, len(s))
    j = m.start(0)
    self._curtoken += s[i:j]
    self._add_token(float(self._curtoken))
    return (self._parse_main, j)
  
  def _parse_keyword(self, s, i):
    m = END_KEYWORD.search(s, i)
    if not m:
      self._curtoken += s[i:]
      return (self._parse_keyword, len(s))
    j = m.start(0)
    self._curtoken += s[i:j]
    if self._curtoken == 'true':
      token = True
    elif self._curtoken == 'false':
      token = False
    else:
      token = KWD(self._curtoken)
    self._add_token(token)
    return (self._parse_main, j)

  def _parse_string(self, s, i):
    m = END_STRING.search(s, i)
    if not m:
      self._curtoken += s[i:]
      return (self._parse_string, len(s))
    j = m.start(0)
    self._curtoken += s[i:j]
    c = s[j]
    if c == '\\':
      self.oct = ''
      return (self._parse_string_1, j+1)
    if c == '(':
      self.paren += 1
      self._curtoken += c
      return (self._parse_string, j+1)
    if c == ')':
      self.paren -= 1
      if self.paren: # WTF, they said balanced parens need no special treatment.
        self._curtoken += c
        return (self._parse_string, j+1)
    self._add_token(self._curtoken)
    return (self._parse_main, j+1)
  
  def _parse_string_1(self, s, i):
    c = s[i]
    if OCT_STRING.match(c) and len(self.oct) < 3:
      self.oct += c
      return (self._parse_string_1, i+1)
    if self.oct:
      self._curtoken += chr(int(self.oct, 8))
      return (self._parse_string, i)
    if c in ESC_STRING:
      self._curtoken += chr(ESC_STRING[c])
    return (self._parse_string, i+1)

  def _parse_wopen(self, s, i):
    c = s[i]
    if c.isspace() or HEX.match(c):
      return (self._parse_hexstring, i)
    if c == '<':
      self._add_token(KEYWORD_DICT_BEGIN)
      i += 1
    return (self._parse_main, i)

  def _parse_wclose(self, s, i):
    c = s[i]
    if c == '>':
      self._add_token(KEYWORD_DICT_END)
      i += 1
    return (self._parse_main, i)

  def _parse_hexstring(self, s, i):
    m = END_HEX_STRING.search(s, i)
    if not m:
      self._curtoken += s[i:]
      return (self._parse_hexstring, len(s))
    j = m.start(0)
    self._curtoken += s[i:j]
    token = HEX_PAIR.sub(lambda m: chr(int(m.group(0), 16)),
                         SPC.sub('', self._curtoken))
    self._add_token(token)
    return (self._parse_main, j)

  def nexttoken(self):
    while not self._tokens:
      self.fillbuf()
      (self._parse1, self.charpos) = self._parse1(self.buf, self.charpos)
    token = self._tokens.pop(0)
    if 2 <= self.debug:
      print >>stderr, 'nexttoken: %r' % (token,)
    return token


##  PSStackParser
##
class PSStackParser(PSBaseParser):

  def __init__(self, fp):
    PSBaseParser.__init__(self, fp)
    self.reset()
    return
  
  def reset(self):
    self.context = []
    self.curtype = None
    self.curstack = []
    self.results = []
    return

  def seek(self, pos):
    PSBaseParser.seek(self, pos)
    self.reset()
    return

  def push(self, *objs):
    self.curstack.extend(objs)
    return
  def pop(self, n):
    objs = self.curstack[-n:]
    self.curstack[-n:] = []
    return objs
  def popall(self):
    objs = self.curstack
    self.curstack = []
    return objs
  def add_results(self, *objs):
    if 2 <= self.debug:
      print >>stderr, 'add_results: %r' % (objs,)
    self.results.extend(objs)
    return

  def start_type(self, pos, type):
    self.context.append((pos, self.curtype, self.curstack))
    (self.curtype, self.curstack) = (type, [])
    if 2 <= self.debug:
      print >>stderr, 'start_type: pos=%r, type=%r' % (pos, type)
    return
  def end_type(self, type):
    if self.curtype != type:
      raise PSTypeError('Type mismatch: %r != %r' % (self.curtype, type))
    objs = [ obj for (_,obj) in self.curstack ]
    (pos, self.curtype, self.curstack) = self.context.pop()
    if 2 <= self.debug:
      print >>stderr, 'end_type: pos=%r, type=%r, objs=%r' % (pos, type, objs)
    return (pos, objs)

  def do_keyword(self, pos, token):
    return
  
  def nextobject(self):
    '''
    Yields a list of objects: keywords, literals, strings, 
    numbers, arrays and dictionaries. Arrays and dictionaries
    are represented as Python sequence and dictionaries.
    '''
    while not self.results:
      (pos, token) = self.nexttoken()
      #print (pos,token), (self.curtype, self.curstack)
      if (isinstance(token, int) or
          isinstance(token, float) or
          isinstance(token, bool) or
          isinstance(token, str) or
          isinstance(token, PSLiteral)):
        # normal token
        self.push((pos, token))
      elif token == KEYWORD_ARRAY_BEGIN:
        # begin array
        self.start_type(pos, 'a')
      elif token == KEYWORD_ARRAY_END:
        # end array
        try:
          self.push(self.end_type('a'))
        except PSTypeError:
          if STRICT: raise
      elif token == KEYWORD_DICT_BEGIN:
        # begin dictionary
        self.start_type(pos, 'd')
      elif token == KEYWORD_DICT_END:
        # end dictionary
        try:
          (pos, objs) = self.end_type('d')
          if len(objs) % 2 != 0:
            raise PSSyntaxError('Invalid dictionary construct: %r' % objs)
          d = dict( (literal_name(k), v) for (k,v) in choplist(2, objs))
          self.push((pos, d))
        except PSTypeError:
          if STRICT: raise
      else:
        if 2 <= self.debug:
          print >>stderr, 'do_keyword: pos=%r, token=%r, stack=%r' % \
                (pos, token, self.curstack)
        self.do_keyword(pos, token)
      if self.context:
        continue
      else:
        self.flush()
    obj = self.results.pop(0)
    if 2 <= self.debug:
      print >>stderr, 'nextobject: %r' % (obj,)
    return obj


##  Simplistic Test cases
##
import unittest
class TestPSBaseParser(unittest.TestCase):

  TESTDATA = r'''%!PS
begin end
 "  @ #
/a/BCD /Some_Name /foo#5f#xbaa
0 +1 -2 .5 1.234
(abc) () (abc ( def ) ghi)
(def\040\0\0404ghi) (bach\\slask) (foo\nbaa)
(this % is not a comment.)
(foo
baa)
(foo\
baa)
<20> < 40 4020 >
<abcd00
12345>
func/a/b{(c)do*}def
[ 1 (z) ! ]
<< /foo (bar) >>
'''
  
  TOKENS = [
    (5, KWD('begin')), (11, KWD('end')), (16, KWD('"')), (19, KWD('@')),
    (21, KWD('#')), (23, LIT('a')), (25, LIT('BCD')), (30, LIT('Some_Name')),
    (41, LIT('foo_xbaa')), (54, 0), (56, 1), (59, -2), (62, 0.5),
    (65, 1.234), (71, 'abc'), (77, ''), (80, 'abc ( def ) ghi'),
    (98, 'def \x00 4ghi'), (118, 'bach\\slask'), (132, 'foo\nbaa'),
    (143, 'this % is not a comment.'), (170, 'foo\nbaa'), (180, 'foobaa'),
    (191, ' '), (196, '@@ '), (208, '\xab\xcd\x00\x124\x05'),
    (223, KWD('func')), (227, LIT('a')), (229, LIT('b')),
    (231, KWD('{')), (232, 'c'), (235, KWD('do*')), (238, KWD('}')),
    (239, KWD('def')), (243, KWD('[')), (245, 1), (247, 'z'), (251, KWD('!')),
    (253, KWD(']')), (255, KWD('<<')), (258, LIT('foo')), (263, 'bar'),
    (269, KWD('>>'))
    ]
  
  OBJS = [
    (23, LIT('a')), (25, LIT('BCD')), (30, LIT('Some_Name')),
    (41, LIT('foo_xbaa')), (54, 0), (56, 1), (59, -2), (62, 0.5),
    (65, 1.234), (71, 'abc'), (77, ''), (80, 'abc ( def ) ghi'),
    (98, 'def \x00 4ghi'), (118, 'bach\\slask'), (132, 'foo\nbaa'),
    (143, 'this % is not a comment.'), (170, 'foo\nbaa'), (180, 'foobaa'),
    (191, ' '), (196, '@@ '), (208, '\xab\xcd\x00\x124\x05'),
    (227, LIT('a')), (229, LIT('b')), (232, 'c'), (243, [1, 'z']),
    (255, {'foo': 'bar'}),
    ]
  
  def get_tokens(self, s):
    import StringIO
    class MyParser(PSBaseParser):
      def flush(self):
        self.add_results(*self.popall())
    parser = MyParser(StringIO.StringIO(s))
    r = []
    try:
      while 1:
        r.append(parser.nexttoken())
    except PSEOF:
      pass
    return r
  
  def get_objects(self, s):
    import StringIO
    class MyParser(PSStackParser):
      def flush(self):
        self.add_results(*self.popall())
    parser = MyParser(StringIO.StringIO(s))
    r = []
    try:
      while 1:
        r.append(parser.nextobject())
    except PSEOF:
      pass
    return r
  
  def test_1(self):
    tokens = self.get_tokens(self.TESTDATA)
    print tokens
    self.assertEqual(tokens, self.TOKENS)
    return

  def test_2(self):
    objs = self.get_objects(self.TESTDATA)
    print objs
    self.assertEqual(objs, self.OBJS)
    return
    
if __name__ == '__main__': unittest.main()
