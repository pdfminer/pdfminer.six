#!/usr/bin/env python

# -*- coding: utf-8 -*-

import re
import logging


from . import settings
from .utils import choplist

log = logging.getLogger(__name__)


class PSException(Exception):
    pass


class PSEOF(PSException):
    pass


class PSSyntaxError(PSException):
    pass


class PSTypeError(PSException):
    pass


class PSValueError(PSException):
    pass


class PSObject:
    """Base class for all PS or PDF-related data types."""

    pass


class PSLiteral(PSObject):

    """A class that represents a PostScript literal.

    Postscript literals are used as identifiers, such as
    variable names, property names and dictionary keys.
    Literals are case sensitive and denoted by a preceding
    slash sign (e.g. "/Name")

    Note: Do not create an instance of PSLiteral directly.
    Always use PSLiteralTable.intern().
    """

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        name = self.name
        return '/%r' % name


class PSKeyword(PSObject):

    """A class that represents a PostScript keyword.

    PostScript keywords are a dozen of predefined words.
    Commands and directives in PostScript are expressed by keywords.
    They are also used to denote the content boundaries.

    Note: Do not create an instance of PSKeyword directly.
    Always use PSKeywordTable.intern().
    """

    def __init__(self, name):
        self.name = name
        return

    def __repr__(self):
        name = self.name
        return '/%r' % name


class PSSymbolTable:
    """A utility class for storing PSLiteral/PSKeyword objects.

    Interned objects can be checked its identity with "is" operator.
    """

    def __init__(self, klass):
        self.dict = {}
        self.klass = klass
        return

    def intern(self, name):
        if name in self.dict:
            lit = self.dict[name]
        else:
            lit = self.klass(name)
            self.dict[name] = lit
        return lit


PSLiteralTable = PSSymbolTable(PSLiteral)
PSKeywordTable = PSSymbolTable(PSKeyword)
LIT = PSLiteralTable.intern
KWD = PSKeywordTable.intern
KEYWORD_PROC_BEGIN = KWD(b'{')
KEYWORD_PROC_END = KWD(b'}')
KEYWORD_ARRAY_BEGIN = KWD(b'[')
KEYWORD_ARRAY_END = KWD(b']')
KEYWORD_DICT_BEGIN = KWD(b'<<')
KEYWORD_DICT_END = KWD(b'>>')


def literal_name(x):
    if not isinstance(x, PSLiteral):
        if settings.STRICT:
            raise PSTypeError('Literal required: {!r}'.format(x))
        else:
            name = x
    else:
        name = x.name
        try:
            name = str(name, 'utf-8')
        except Exception:
            pass
    return name


def keyword_name(x):
    if not isinstance(x, PSKeyword):
        if settings.STRICT:
            raise PSTypeError('Keyword required: %r' % x)
        else:
            name = x
    else:
        name = str(x.name, 'utf-8', 'ignore')
    return name


EOL = re.compile(br'[\r\n]')
SPC = re.compile(br'\s')
NONSPC = re.compile(br'\S')
HEX = re.compile(br'[0-9a-fA-F]')
END_LITERAL = re.compile(br'[#/%\[\]()<>{}\s]')
END_HEX_STRING = re.compile(br'[^\s0-9a-fA-F]')
HEX_PAIR = re.compile(br'[0-9a-fA-F]{2}|.')
END_NUMBER = re.compile(br'[^0-9]')
END_KEYWORD = re.compile(br'[#/%\[\]()<>{}\s]')
END_STRING = re.compile(br'[()\134]')
OCT_STRING = re.compile(br'[0-7]')
ESC_STRING = {
    b'b': 8,
    b't': 9,
    b'n': 10,
    b'f': 12,
    b'r': 13,
    b'(': 40,
    b')': 41,
    b'\\': 92
}


class PSBaseParser:

    """Most basic PostScript parser that performs only tokenization.
    """
    BUFSIZ = 4096

    def __init__(self, fp):
        self.fp = fp
        self.seek(0)
        return

    def __repr__(self):
        return '<%s: %r, bufpos=%d>' % (self.__class__.__name__, self.fp,
                                        self.bufpos)

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
        log.info('poll(%d): %r', pos, self.fp.read(n))
        self.fp.seek(pos0)
        return

    def seek(self, pos):
        """Seeks the parser to the given position.
        """
        log.debug('seek: %r', pos)
        self.fp.seek(pos)
        # reset the status for nextline()
        self.bufpos = pos
        self.buf = b''
        self.charpos = 0
        # reset the status for nexttoken()
        self._parse1 = self._parse_main
        self._curtoken = b''
        self._curtokenpos = 0
        self._tokens = []
        return

    def fillbuf(self):
        if self.charpos < len(self.buf):
            return
        # fetch next chunk.
        self.bufpos = self.fp.tell()
        self.buf = self.fp.read(self.BUFSIZ)
        if not self.buf:
            raise PSEOF('Unexpected EOF')
        self.charpos = 0
        return

    def nextline(self):
        """Fetches a next line that ends either with \\r or \\n.
        """
        linebuf = b''
        linepos = self.bufpos + self.charpos
        eol = False
        while 1:
            self.fillbuf()
            if eol:
                c = self.buf[self.charpos:self.charpos+1]
                # handle b'\r\n'
                if c == b'\n':
                    linebuf += c
                    self.charpos += 1
                break
            m = EOL.search(self.buf, self.charpos)
            if m:
                linebuf += self.buf[self.charpos:m.end(0)]
                self.charpos = m.end(0)
                if linebuf[-1:] == b'\r':
                    eol = True
                else:
                    break
            else:
                linebuf += self.buf[self.charpos:]
                self.charpos = len(self.buf)
        log.debug('nextline: %r, %r', linepos, linebuf)

        return (linepos, linebuf)

    def revreadlines(self):
        """Fetches a next line backword.

        This is used to locate the trailers at the end of a file.
        """
        self.fp.seek(0, 2)
        pos = self.fp.tell()
        buf = b''
        while 0 < pos:
            prevpos = pos
            pos = max(0, pos-self.BUFSIZ)
            self.fp.seek(pos)
            s = self.fp.read(prevpos-pos)
            if not s:
                break
            while 1:
                n = max(s.rfind(b'\r'), s.rfind(b'\n'))
                if n == -1:
                    buf = s + buf
                    break
                yield s[n:] + buf
                s = s[:n]
                buf = b''
        return

    def _parse_main(self, s, i):
        m = NONSPC.search(s, i)
        if not m:
            return len(s)
        j = m.start(0)
        c = s[j:j+1]
        self._curtokenpos = self.bufpos+j
        if c == b'%':
            self._curtoken = b'%'
            self._parse1 = self._parse_comment
            return j+1
        elif c == b'/':
            self._curtoken = b''
            self._parse1 = self._parse_literal
            return j+1
        elif c in b'-+' or c.isdigit():
            self._curtoken = c
            self._parse1 = self._parse_number
            return j+1
        elif c == b'.':
            self._curtoken = c
            self._parse1 = self._parse_float
            return j+1
        elif c.isalpha():
            self._curtoken = c
            self._parse1 = self._parse_keyword
            return j+1
        elif c == b'(':
            self._curtoken = b''
            self.paren = 1
            self._parse1 = self._parse_string
            return j+1
        elif c == b'<':
            self._curtoken = b''
            self._parse1 = self._parse_wopen
            return j+1
        elif c == b'>':
            self._curtoken = b''
            self._parse1 = self._parse_wclose
            return j+1
        else:
            self._add_token(KWD(c))
            return j+1

    def _add_token(self, obj):
        self._tokens.append((self._curtokenpos, obj))
        return

    def _parse_comment(self, s, i):
        m = EOL.search(s, i)
        if not m:
            self._curtoken += s[i:]
            return len(s)
        j = m.start(0)
        self._curtoken += s[i:j]
        self._parse1 = self._parse_main
        # We ignore comments.
        # self._tokens.append(self._curtoken)
        return j

    def _parse_literal(self, s, i):
        m = END_LITERAL.search(s, i)
        if not m:
            self._curtoken += s[i:]
            return len(s)
        j = m.start(0)
        self._curtoken += s[i:j]
        c = s[j:j+1]
        if c == b'#':
            self.hex = b''
            self._parse1 = self._parse_literal_hex
            return j+1
        try:
            self._curtoken = str(self._curtoken, 'utf-8')
        except Exception:
            pass
        self._add_token(LIT(self._curtoken))
        self._parse1 = self._parse_main
        return j

    def _parse_literal_hex(self, s, i):
        c = s[i:i+1]
        if HEX.match(c) and len(self.hex) < 2:
            self.hex += c
            return i+1
        if self.hex:
            self._curtoken += bytes((int(self.hex, 16),))
        self._parse1 = self._parse_literal
        return i

    def _parse_number(self, s, i):
        m = END_NUMBER.search(s, i)
        if not m:
            self._curtoken += s[i:]
            return len(s)
        j = m.start(0)
        self._curtoken += s[i:j]
        c = s[j:j+1]
        if c == b'.':
            self._curtoken += c
            self._parse1 = self._parse_float
            return j+1
        try:
            self._add_token(int(self._curtoken))
        except ValueError:
            pass
        self._parse1 = self._parse_main
        return j

    def _parse_float(self, s, i):
        m = END_NUMBER.search(s, i)
        if not m:
            self._curtoken += s[i:]
            return len(s)
        j = m.start(0)
        self._curtoken += s[i:j]
        try:
            self._add_token(float(self._curtoken))
        except ValueError:
            pass
        self._parse1 = self._parse_main
        return j

    def _parse_keyword(self, s, i):
        m = END_KEYWORD.search(s, i)
        if not m:
            self._curtoken += s[i:]
            return len(s)
        j = m.start(0)
        self._curtoken += s[i:j]
        if self._curtoken == b'true':
            token = True
        elif self._curtoken == b'false':
            token = False
        else:
            token = KWD(self._curtoken)
        self._add_token(token)
        self._parse1 = self._parse_main
        return j

    def _parse_string(self, s, i):
        m = END_STRING.search(s, i)
        if not m:
            self._curtoken += s[i:]
            return len(s)
        j = m.start(0)
        self._curtoken += s[i:j]
        c = s[j:j+1]
        if c == b'\\':
            self.oct = b''
            self._parse1 = self._parse_string_1
            return j+1
        if c == b'(':
            self.paren += 1
            self._curtoken += c
            return j+1
        if c == b')':
            self.paren -= 1
            if self.paren:
                # WTF, they said balanced parens need no special treatment.
                self._curtoken += c
                return j+1
        self._add_token(self._curtoken)
        self._parse1 = self._parse_main
        return j+1

    def _parse_string_1(self, s, i):
        c = s[i:i+1]
        if OCT_STRING.match(c) and len(self.oct) < 3:
            self.oct += c
            return i+1
        if self.oct:
            self._curtoken += bytes((int(self.oct, 8),))
            self._parse1 = self._parse_string
            return i
        if c in ESC_STRING:
            self._curtoken += bytes((ESC_STRING[c],))
        self._parse1 = self._parse_string
        return i+1

    def _parse_wopen(self, s, i):
        c = s[i:i+1]
        if c == b'<':
            self._add_token(KEYWORD_DICT_BEGIN)
            self._parse1 = self._parse_main
            i += 1
        else:
            self._parse1 = self._parse_hexstring
        return i

    def _parse_wclose(self, s, i):
        c = s[i:i+1]
        if c == b'>':
            self._add_token(KEYWORD_DICT_END)
            i += 1
        self._parse1 = self._parse_main
        return i

    def _parse_hexstring(self, s, i):
        m = END_HEX_STRING.search(s, i)
        if not m:
            self._curtoken += s[i:]
            return len(s)
        j = m.start(0)
        self._curtoken += s[i:j]
        token = HEX_PAIR.sub(lambda m: bytes((int(m.group(0), 16),)),
                             SPC.sub(b'', self._curtoken))
        self._add_token(token)
        self._parse1 = self._parse_main
        return j

    def nexttoken(self):
        while not self._tokens:
            self.fillbuf()
            self.charpos = self._parse1(self.buf, self.charpos)
        token = self._tokens.pop(0)
        log.debug('nexttoken: %r', token)
        return token


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
        try:
            log.debug('add_results: %r', objs)
        except Exception:
            log.debug('add_results: (unprintable object)')
        self.results.extend(objs)
        return

    def start_type(self, pos, type):
        self.context.append((pos, self.curtype, self.curstack))
        (self.curtype, self.curstack) = (type, [])
        log.debug('start_type: pos=%r, type=%r', pos, type)
        return

    def end_type(self, type):
        if self.curtype != type:
            raise PSTypeError('Type mismatch: {!r} != {!r}'
                              .format(self.curtype, type))
        objs = [obj for (_, obj) in self.curstack]
        (pos, self.curtype, self.curstack) = self.context.pop()
        log.debug('end_type: pos=%r, type=%r, objs=%r', pos, type, objs)
        return (pos, objs)

    def do_keyword(self, pos, token):
        return

    def nextobject(self):
        """Yields a list of objects.

        Arrays and dictionaries are represented as Python lists and
        dictionaries.

        :return: keywords, literals, strings, numbers, arrays and dictionaries.
        """
        while not self.results:
            (pos, token) = self.nexttoken()
            if isinstance(token, (int, float, bool, str, bytes, PSLiteral)):
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
                    if settings.STRICT:
                        raise
            elif token == KEYWORD_DICT_BEGIN:
                # begin dictionary
                self.start_type(pos, 'd')
            elif token == KEYWORD_DICT_END:
                # end dictionary
                try:
                    (pos, objs) = self.end_type('d')
                    if len(objs) % 2 != 0:
                        error_msg = 'Invalid dictionary construct: %r' % objs
                        raise PSSyntaxError(error_msg)
                    d = {literal_name(k): v
                         for (k, v) in choplist(2, objs) if v is not None}
                    self.push((pos, d))
                except PSTypeError:
                    if settings.STRICT:
                        raise
            elif token == KEYWORD_PROC_BEGIN:
                # begin proc
                self.start_type(pos, 'p')
            elif token == KEYWORD_PROC_END:
                # end proc
                try:
                    self.push(self.end_type('p'))
                except PSTypeError:
                    if settings.STRICT:
                        raise
            elif isinstance(token, PSKeyword):
                log.debug('do_keyword: pos=%r, token=%r, stack=%r', pos,
                          token, self.curstack)
                self.do_keyword(pos, token)
            else:
                log.error('unknown token: pos=%r, token=%r, stack=%r', pos,
                          token, self.curstack)
                self.do_keyword(pos, token)
                raise
            if self.context:
                continue
            else:
                self.flush()
        obj = self.results.pop(0)
        try:
            log.debug('nextobject: %r', obj)
        except Exception:
            log.debug('nextobject: (unprintable object)')
        return obj
