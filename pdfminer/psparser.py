#!/usr/bin/env python3
import io
import logging
import re
from binascii import unhexlify
from collections import deque
from typing import (
    Any,
    BinaryIO,
    Deque,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from pdfminer import psexceptions, settings
from pdfminer.utils import choplist

log = logging.getLogger(__name__)


# Adding aliases for these exceptions for backwards compatibility
PSException = psexceptions.PSException
PSEOF = psexceptions.PSEOF
PSSyntaxError = psexceptions.PSSyntaxError
PSTypeError = psexceptions.PSTypeError
PSValueError = psexceptions.PSValueError


class PSObject:
    """Base class for all PS or PDF-related data types."""


class PSLiteral(PSObject):
    """A class that represents a PostScript literal.

    Postscript literals are used as identifiers, such as
    variable names, property names and dictionary keys.
    Literals are case sensitive and denoted by a preceding
    slash sign (e.g. "/Name")

    Note: Do not create an instance of PSLiteral directly.
    Always use PSLiteralTable.intern().
    """

    NameType = Union[str, bytes]

    def __init__(self, name: NameType) -> None:
        self.name = name

    def __repr__(self) -> str:
        name = self.name
        return "/%r" % name


class PSKeyword(PSObject):
    """A class that represents a PostScript keyword.

    PostScript keywords are a dozen of predefined words.
    Commands and directives in PostScript are expressed by keywords.
    They are also used to denote the content boundaries.

    Note: Do not create an instance of PSKeyword directly.
    Always use PSKeywordTable.intern().
    """

    def __init__(self, name: bytes) -> None:
        self.name = name

    def __repr__(self) -> str:
        name = self.name
        return "/%r" % name


_SymbolT = TypeVar("_SymbolT", PSLiteral, PSKeyword)


class PSSymbolTable(Generic[_SymbolT]):
    """A utility class for storing PSLiteral/PSKeyword objects.

    Interned objects can be checked its identity with "is" operator.
    """

    def __init__(self, klass: Type[_SymbolT]) -> None:
        self.dict: Dict[PSLiteral.NameType, _SymbolT] = {}
        self.klass: Type[_SymbolT] = klass

    def intern(self, name: PSLiteral.NameType) -> _SymbolT:
        if name in self.dict:
            lit = self.dict[name]
        else:
            # Type confusion issue: PSKeyword always takes bytes as name
            #                       PSLiteral uses either str or bytes
            lit = self.klass(name)  # type: ignore[arg-type]
            self.dict[name] = lit
        return lit


PSLiteralTable = PSSymbolTable(PSLiteral)
PSKeywordTable = PSSymbolTable(PSKeyword)
LIT = PSLiteralTable.intern
KWD = PSKeywordTable.intern
KEYWORD_PROC_BEGIN = KWD(b"{")
KEYWORD_PROC_END = KWD(b"}")
KEYWORD_ARRAY_BEGIN = KWD(b"[")
KEYWORD_ARRAY_END = KWD(b"]")
KEYWORD_DICT_BEGIN = KWD(b"<<")
KEYWORD_DICT_END = KWD(b">>")
KEYWORD_GT = KWD(b">")


def literal_name(x: Any) -> str:
    if isinstance(x, PSLiteral):
        if isinstance(x.name, str):
            return x.name
        try:
            return str(x.name, "utf-8")
        except UnicodeDecodeError:
            return str(x.name)
    else:
        if settings.STRICT:
            raise PSTypeError(f"Literal required: {x!r}")
        return str(x)


def keyword_name(x: Any) -> Any:
    if not isinstance(x, PSKeyword):
        if settings.STRICT:
            raise PSTypeError("Keyword required: %r" % x)
        else:
            name = x
    else:
        name = str(x.name, "utf-8", "ignore")
    return name


EOL = b"\r\n"
WHITESPACE = b" \t\n\r\f\v"
NUMBER = b"0123456789"
HEX = NUMBER + b"abcdef" + b"ABCDEF"
NOTLITERAL = b"#/%[]()<>{}" + WHITESPACE
NOTKEYWORD = b"#/%[]()<>{}" + WHITESPACE
NOTSTRING = b"()\\"
OCTAL = b"01234567"
ESC_STRING = {
    b"b": 8,
    b"t": 9,
    b"n": 10,
    b"f": 12,
    b"r": 13,
    b"(": 40,
    b")": 41,
    b"\\": 92,
}


PSBaseParserToken = Union[float, bool, PSLiteral, PSKeyword, bytes]


class PSFileParser:
    """
    Parser (actually a lexer) for PDF data from a buffered file object.
    """

    def __init__(self, fp: BinaryIO) -> None:
        self.fp = fp
        self._tokens: Deque[Tuple[int, PSBaseParserToken]] = deque()
        self.seek(0)

    def reinit(self, fp: BinaryIO) -> None:
        """Reinitialize parser with a new file."""
        self.fp = fp
        self.seek(0)

    def seek(self, pos: int) -> None:
        """Seek to a position and reinitialize parser state."""
        self.fp.seek(pos)
        self._parse1 = self._parse_main
        self._curtoken = b""
        self._curtokenpos = 0
        self._tokens.clear()

    def tell(self) -> int:
        """Get the current position in the file."""
        return self.fp.tell()

    def read(self, pos: int, objlen: int) -> bytes:
        """Read data from a specified position, moving the current
        position to the end of this data."""
        self.fp.seek(pos)
        return self.fp.read(objlen)

    def nextline(self) -> Tuple[int, bytes]:
        r"""Fetches a next line that ends either with \r, \n, or
        \r\n."""
        linepos = self.fp.tell()
        # readline() is implemented on BinarIO so just use that
        # (except that it only accepts \n as a separator)
        line_or_lines = self.fp.readline()
        if line_or_lines == b"":
            raise PSEOF
        first, sep, rest = line_or_lines.partition(b"\r")
        if len(rest) == 0:
            return (linepos, line_or_lines)
        elif rest != b"\n":
            self.fp.seek(linepos + len(first) + 1)
            return (linepos, first + sep)
        else:
            self.fp.seek(linepos + len(first) + 2)
            return (linepos, first + b"\r\n")

    def revreadlines(self) -> Iterator[bytes]:
        """Fetches a next line backwards.

        This is used to locate the trailers at the end of a file.
        """
        self.fp.seek(0, io.SEEK_END)
        pos = self.fp.tell()
        buf = b""
        while pos > 0:
            # NOTE: This can obviously be optimized to use regular
            # expressions on the (known to exist) buffer in
            # self.fp...
            pos -= 1
            self.fp.seek(pos)
            c = self.fp.read(1)
            if c in b"\r\n":
                yield buf
                buf = c
                if c == b"\n" and pos > 0:
                    self.fp.seek(pos - 1)
                    cc = self.fp.read(1)
                    if cc == b"\r":
                        pos -= 1
                        buf = cc + buf
            else:
                buf = c + buf
        yield buf

    def get_inline_data(
        self, target: bytes = b"EI", blocksize: int = 4096
    ) -> Tuple[int, bytes]:
        """Get the data for an inline image up to the target
        end-of-stream marker.

        Returns a tuple of the position of the target in the data and the
        data *including* the end of stream marker.  Advances the file
        pointer to a position after the end of the stream.

        The caller is responsible for removing the end-of-stream if
        necessary (this depends on the filter being used) and parsing
        the end-of-stream token (likewise) if necessary.
        """
        # PDF 1.7, p. 216: The bytes between the ID and EI operators
        # shall be treated the same as a stream object’s data (see
        # 7.3.8, "Stream Objects"), even though they do not follow the
        # standard stream syntax.
        data = []  # list of blocks
        partial = b""  # partially seen target
        pos = 0
        while True:
            # Did we see part of the target at the end of the last
            # block?  Then scan ahead and try to find the rest (we
            # assume the stream is buffered)
            if partial:
                extra_len = len(target) - len(partial)
                extra = self.fp.read(extra_len)
                if partial + extra == target:
                    pos -= len(partial)
                    data.append(extra)
                    break
                # Put it back (assume buffering!)
                self.fp.seek(-extra_len, io.SEEK_CUR)
                partial = b""
                # Fall through (the target could be at the beginning)
            buf = self.fp.read(blocksize)
            if not buf:
                return (-1, b"")
            tpos = buf.find(target)
            if tpos != -1:
                data.append(buf[: tpos + len(target)])
                # Put the extra back (assume buffering!)
                self.fp.seek(tpos - len(buf) + len(target), io.SEEK_CUR)
                pos += tpos
                break
            else:
                pos += len(buf)
                # look for the longest partial match at the end
                plen = len(target) - 1
                while plen > 0:
                    ppos = len(buf) - plen
                    if buf[ppos:] == target[:plen]:
                        partial = buf[ppos:]
                        break
                    plen -= 1
                data.append(buf)
        return (pos, b"".join(data))

    def __iter__(self) -> Iterator[Tuple[int, PSBaseParserToken]]:
        """Iterate over tokens."""
        return self

    def __next__(self) -> Tuple[int, PSBaseParserToken]:
        """Get the next token in iteration, raising StopIteration when
        done."""
        while True:
            c = self._parse1()
            # print(c, self._curtoken, self._parse1)
            if self._tokens or c == b"":
                break
        if not self._tokens:
            raise StopIteration
        return self._tokens.popleft()

    def nexttoken(self) -> Tuple[int, PSBaseParserToken]:
        """Get the next token in iteration, raising PSEOF when done."""
        try:
            return self.__next__()
        except StopIteration:
            raise PSEOF

    def _parse_main(self) -> bytes:
        """Initial/default state for the lexer."""
        c = self.fp.read(1)
        # note that b"" (EOF) is in everything, which is fine
        if c in WHITESPACE:
            return c
        self._curtokenpos = self.fp.tell() - 1
        if c == b"%":
            self._curtoken = b"%"
            self._parse1 = self._parse_comment
        elif c == b"/":
            self._curtoken = b""
            self._parse1 = self._parse_literal
        elif c in b"-+" or c in NUMBER:
            self._curtoken = c
            self._parse1 = self._parse_number
        elif c == b".":
            self._curtoken = c
            self._parse1 = self._parse_float
        elif c.isalpha():
            self._curtoken = c
            self._parse1 = self._parse_keyword
        elif c == b"(":
            self._curtoken = b""
            self.paren = 1
            self._parse1 = self._parse_string
        elif c == b"<":
            self._curtoken = b""
            self._parse1 = self._parse_wopen
        elif c == b">":
            self._curtoken = b""
            self._parse1 = self._parse_wclose
        elif c == b"\x00":
            pass
        else:
            self._add_token(KWD(c))
        return c

    def _add_token(self, obj: PSBaseParserToken) -> None:
        """Add a succesfully parsed token."""
        self._tokens.append((self._curtokenpos, obj))

    def _parse_comment(self) -> bytes:
        """Comment state for the lexer"""
        c = self.fp.read(1)
        if c in EOL:  # this includes b"", i.e. EOF
            self._parse1 = self._parse_main
            # We ignore comments.
            # self._tokens.append(self._curtoken)
        else:
            self._curtoken += c
        return c

    def _parse_literal(self) -> bytes:
        """Literal (keyword) state for the lexer."""
        c = self.fp.read(1)
        if c == b"#":
            self.hex = b""
            self._parse1 = self._parse_literal_hex
        elif c in NOTLITERAL:
            if c:
                self.fp.seek(-1, io.SEEK_CUR)
            try:
                self._add_token(LIT(self._curtoken.decode("utf-8")))
            except UnicodeDecodeError:
                self._add_token(LIT(self._curtoken))
            self._parse1 = self._parse_main
        else:
            self._curtoken += c
        return c

    def _parse_literal_hex(self) -> bytes:
        """State for escaped hex characters in literal names"""
        # Consume a hex digit only if we can ... consume a hex digit
        if len(self.hex) >= 2:  # it actually can't exceed 2
            self._curtoken += bytes((int(self.hex, 16),))
            self._parse1 = self._parse_literal
            return b"/"
        c = self.fp.read(1)
        if c and c in HEX:
            self.hex += c
        else:
            if c:  # not EOF, but not hex either
                log.warning("Invalid hex digit %r in literal", c)
                self.fp.seek(-1, io.SEEK_CUR)
                # Add the intervening junk, just in case
                try:
                    tok = LIT(self._curtoken.decode("utf-8"))
                except UnicodeDecodeError:
                    tok = LIT(self._curtoken)
                self._add_token(tok)
                self._curtokenpos = self.tell() - 1 - len(self.hex)
                self._add_token(KWD(b"#" + self.hex))
            self._parse1 = self._parse_main
        return c

    def _parse_number(self) -> bytes:
        """State for numeric objects."""
        c = self.fp.read(1)
        if c and c in NUMBER:
            self._curtoken += c
        elif c == b".":
            self._curtoken += c
            self._parse1 = self._parse_float
        else:
            if c:
                self.fp.seek(-1, io.SEEK_CUR)
            try:
                self._add_token(int(self._curtoken))
            except ValueError:
                log.warning("Invalid int literal: %r", self._curtoken)
            self._parse1 = self._parse_main
        return c

    def _parse_float(self) -> bytes:
        """State for fractional part of numeric objects."""
        c = self.fp.read(1)
        # b"" is in everything so we have to add an extra check
        if not c or c not in NUMBER:
            if c:
                self.fp.seek(-1, io.SEEK_CUR)
            try:
                self._add_token(float(self._curtoken))
            except ValueError:
                log.warning("Invalid float literal: %r", self._curtoken)
            self._parse1 = self._parse_main
        else:
            self._curtoken += c
        return c

    def _parse_keyword(self) -> bytes:
        """State for keywords."""
        c = self.fp.read(1)
        if c in NOTKEYWORD:  # includes EOF
            if c:
                self.fp.seek(-1, io.SEEK_CUR)
            if self._curtoken == b"true":
                self._add_token(True)
            elif self._curtoken == b"false":
                self._add_token(False)
            else:
                self._add_token(KWD(self._curtoken))
            self._parse1 = self._parse_main
        else:
            self._curtoken += c
        return c

    def _parse_string(self) -> bytes:
        """State for string objects."""
        c = self.fp.read(1)
        if c and c in NOTSTRING:  # does not include EOF
            if c == b"\\":
                self._parse1 = self._parse_string_esc
                return c
            elif c == b"(":
                self.paren += 1
                self._curtoken += c
                return c
            elif c == b")":
                self.paren -= 1
                if self.paren:
                    self._curtoken += c
                    return c
            # We saw the last parenthesis and fell through (it will be
            # consumed, but not added to self._curtoken)
            self._add_token(self._curtoken)
            self._parse1 = self._parse_main
        elif c == b"\r":
            # PDF 1.7 page 15: An end-of-line marker appearing within
            # a literal string without a preceding REVERSE SOLIDUS
            # shall be treated as a byte value of (0Ah), irrespective
            # of whether the end-of-line marker was a CARRIAGE RETURN
            # (0Dh), a LINE FEED (0Ah), or both.
            cc = self.fp.read(1)
            # Put it back if it isn't \n
            if cc and cc != b"\n":
                self.fp.seek(-1, io.SEEK_CUR)
            self._curtoken += b"\n"
        else:
            self._curtoken += c
        return c

    def _parse_string_esc(self) -> bytes:
        """State for escapes in literal strings.  We have seen a
        backslash and nothing else."""
        c = self.fp.read(1)
        if c and c in OCTAL:  # exclude EOF
            self.oct = c
            self._parse1 = self._parse_string_octal
            return c
        elif c and c in ESC_STRING:
            self._curtoken += bytes((ESC_STRING[c],))
        elif c == b"\n":  # Skip newline after backslash
            pass
        elif c == b"\r":  # Also skip CRLF after
            cc = self.fp.read(1)
            # Put it back if it isn't \n
            if cc and cc != b"\n":
                self.fp.seek(-1, io.SEEK_CUR)
        elif c == b"":
            log.warning("EOF inside escape %r", self._curtoken)
        else:
            log.warning("Unrecognized escape %r", c)
            self._curtoken += c
        self._parse1 = self._parse_string
        return c

    def _parse_string_octal(self) -> bytes:
        """State for an octal escape."""
        c = self.fp.read(1)
        if c and c in OCTAL:  # exclude EOF
            self.oct += c
            done = len(self.oct) >= 3  # it can't be > though
        else:
            if c:
                self.fp.seek(-1, io.SEEK_CUR)
            else:
                log.warning("EOF in octal escape %r", self._curtoken)
            done = True
        if done:
            chrcode = int(self.oct, 8)
            if chrcode >= 256:
                # PDF1.7 p.16: "high-order overflow shall be ignored."
                log.warning("Invalid octal %r (%d)", self.oct, chrcode)
            else:
                self._curtoken += bytes((chrcode,))
            # Back to normal string parsing
            self._parse1 = self._parse_string
        return c

    def _parse_wopen(self) -> bytes:
        """State for start of dictionary or hex string."""
        c = self.fp.read(1)
        if c == b"<":
            self._add_token(KEYWORD_DICT_BEGIN)
            self._parse1 = self._parse_main
        else:
            if c:
                self.fp.seek(-1, io.SEEK_CUR)
            self._parse1 = self._parse_hexstring
        return c

    def _parse_wclose(self) -> bytes:
        """State for end of dictionary (accessed from initial state only)"""
        c = self.fp.read(1)
        if c == b">":
            self._add_token(KEYWORD_DICT_END)
        else:
            # Assuming this is a keyword (which means nothing)
            self._add_token(KEYWORD_GT)
            if c:
                self.fp.seek(-1, io.SEEK_CUR)
        self._parse1 = self._parse_main
        return c

    def _parse_hexstring(self) -> bytes:
        """State for parsing hexadecimal literal strings."""
        c = self.fp.read(1)
        if not c:
            log.warning("EOF in hex string %r", self._curtoken)
        elif c in WHITESPACE:
            pass
        elif c in HEX:
            self._curtoken += c
        elif c == b">":
            if len(self._curtoken) % 2 == 1:
                self._curtoken += b"0"
            token = unhexlify(self._curtoken)
            self._add_token(token)
            self._parse1 = self._parse_main
        else:
            log.warning("unexpected character %r in hex string %r", c, self._curtoken)
        return c


LEXER = re.compile(
    rb"""(?:
      (?P<whitespace> \s+)
    | (?P<comment> %[^\r\n]*[\r\n])
    | (?P<name> /(?: \#[A-Fa-f\d][A-Fa-f\d] | [^#/%\[\]()<>{}\s])+ )
    | (?P<number> [-+]? (?: \d*\.\d+ | \d+ ) )
    | (?P<keyword> [A-Za-z] [^#/%\[\]()<>{}\s]*)
    | (?P<startstr> \([^()\\]*)
    | (?P<hexstr> <[A-Fa-f\d\s]*>)
    | (?P<startdict> <<)
    | (?P<enddict> >>)
    | (?P<other> .)
)
""",
    re.VERBOSE,
)
STRLEXER = re.compile(
    rb"""(?:
      (?P<octal> \\[0-7]{1,3})
    | (?P<linebreak> \\(?:\r\n?|\n))
    | (?P<escape> \\.)
    | (?P<parenleft> \()
    | (?P<parenright> \))
    | (?P<newline> \r\n?|\n)
    | (?P<other> .)
)""",
    re.VERBOSE,
)
HEXDIGIT = re.compile(rb"#([A-Fa-f\d][A-Fa-f\d])")
EOLR = re.compile(rb"\r\n?|\n")
SPC = re.compile(rb"\s")


class PSInMemoryParser:
    """
    Parser for in-memory data streams.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.end = len(data)
        self._tokens: Deque[Tuple[int, PSBaseParserToken]] = deque()

    def reinit(self, data: bytes) -> None:
        """Reinitialize parser with a new buffer."""
        self.data = data
        self.seek(0)

    def seek(self, pos: int) -> None:
        """Seek to a position and reinitialize parser state."""
        self.pos = pos
        self._curtoken = b""
        self._curtokenpos = 0
        self._tokens.clear()

    def tell(self) -> int:
        """Get the current position in the buffer."""
        return self.pos

    def read(self, pos: int, objlen: int) -> bytes:
        """Read data from a specified position, moving the current
        position to the end of this data."""
        self.pos = min(pos + objlen, len(self.data))
        return self.data[pos : self.pos]

    def nextline(self) -> Tuple[int, bytes]:
        r"""Fetches a next line that ends either with \r, \n, or \r\n."""
        if self.pos == self.end:
            raise PSEOF
        linepos = self.pos
        m = EOLR.search(self.data, self.pos)
        if m is None:
            self.pos = self.end
        else:
            self.pos = m.end()
        return (linepos, self.data[linepos : self.pos])

    def revreadlines(self) -> Iterator[bytes]:
        """Fetches a next line backwards.

        This is used to locate the trailers at the end of a file.  So,
        it isn't actually used in PSInMemoryParser, but is here for
        completeness.
        """
        endline = pos = self.end
        while True:
            nidx = self.data.rfind(b"\n", 0, pos)
            ridx = self.data.rfind(b"\r", 0, pos)
            best = max(nidx, ridx)
            if best == -1:
                yield self.data[:endline]
                break
            yield self.data[best + 1 : endline]
            endline = best + 1
            pos = best
            if pos > 0 and self.data[pos - 1 : pos + 1] == b"\r\n":
                pos -= 1

    def get_inline_data(
        self, target: bytes = b"EI", blocksize: int = -1
    ) -> Tuple[int, bytes]:
        """Get the data for an inline image up to the target
        end-of-stream marker.

        Returns a tuple of the position of the target in the data and the
        data *including* the end of stream marker.  Advances the file
        pointer to a position after the end of the stream.

        The caller is responsible for removing the end-of-stream if
        necessary (this depends on the filter being used) and parsing
        the end-of-stream token (likewise) if necessary.
        """
        tpos = self.data.find(target, self.pos)
        if tpos != -1:
            nextpos = tpos + len(target)
            result = (tpos, self.data[self.pos : nextpos])
            self.pos = nextpos
            return result
        return (-1, b"")

    def __iter__(self) -> Iterator[Tuple[int, PSBaseParserToken]]:
        """Iterate over tokens."""
        return self

    def nexttoken(self) -> Tuple[int, PSBaseParserToken]:
        """Get the next token in iteration, raising PSEOF when done."""
        try:
            return self.__next__()
        except StopIteration:
            raise PSEOF

    def __next__(self) -> Tuple[int, PSBaseParserToken]:
        """Get the next token in iteration, raising StopIteration when
        done."""
        while True:
            m = LEXER.match(self.data, self.pos)
            if m is None:  # can only happen at EOS
                raise StopIteration
            self._curtokenpos = m.start()
            self.pos = m.end()
            if m.lastgroup not in ("whitespace", "comment"):  # type: ignore
                # Okay, we got a token or something
                break
        self._curtoken = m[0]
        if m.lastgroup == "name":  # type: ignore
            self._curtoken = m[0][1:]
            self._curtoken = HEXDIGIT.sub(
                lambda x: bytes((int(x[1], 16),)), self._curtoken
            )
            try:
                tok = LIT(self._curtoken.decode("utf-8"))
            except UnicodeDecodeError:
                tok = LIT(self._curtoken)
            return (self._curtokenpos, tok)
        if m.lastgroup == "number":  # type: ignore
            if b"." in self._curtoken:
                return (self._curtokenpos, float(self._curtoken))
            else:
                return (self._curtokenpos, int(self._curtoken))
        if m.lastgroup == "startdict":  # type: ignore
            return (self._curtokenpos, KEYWORD_DICT_BEGIN)
        if m.lastgroup == "enddict":  # type: ignore
            return (self._curtokenpos, KEYWORD_DICT_END)
        if m.lastgroup == "startstr":  # type: ignore
            return self._parse_endstr(self.data[m.start() + 1 : m.end()], m.end())
        if m.lastgroup == "hexstr":  # type: ignore
            self._curtoken = SPC.sub(b"", self._curtoken[1:-1])
            if len(self._curtoken) % 2 == 1:
                self._curtoken += b"0"
            return (self._curtokenpos, unhexlify(self._curtoken))
        # Anything else is treated as a keyword (whether explicitly matched or not)
        if self._curtoken == b"true":
            return (self._curtokenpos, True)
        elif self._curtoken == b"false":
            return (self._curtokenpos, False)
        else:
            return (self._curtokenpos, KWD(self._curtoken))

    def _parse_endstr(self, start: bytes, pos: int) -> Tuple[int, PSBaseParserToken]:
        """Parse the remainder of a string."""
        # Handle nonsense CRLF conversion in strings (PDF 1.7, p.15)
        parts = [EOLR.sub(b"\n", start)]
        paren = 1
        for m in STRLEXER.finditer(self.data, pos):
            self.pos = m.end()
            if m.lastgroup == "parenright":  # type: ignore
                paren -= 1
                if paren == 0:
                    # By far the most common situation!
                    break
                parts.append(m[0])
            elif m.lastgroup == "parenleft":  # type: ignore
                parts.append(m[0])
                paren += 1
            elif m.lastgroup == "escape":  # type: ignore
                chr = m[0][1:2]
                if chr not in ESC_STRING:
                    log.warning("Unrecognized escape %r", m[0])
                    parts.append(chr)
                else:
                    parts.append(bytes((ESC_STRING[chr],)))
            elif m.lastgroup == "octal":  # type: ignore
                chrcode = int(m[0][1:], 8)
                if chrcode >= 256:
                    # PDF1.7 p.16: "high-order overflow shall be
                    # ignored."
                    log.warning("Invalid octal %r (%d)", m[0][1:], chrcode)
                else:
                    parts.append(bytes((chrcode,)))
            elif m.lastgroup == "newline":  # type: ignore
                # Handle nonsense CRLF conversion in strings (PDF 1.7, p.15)
                parts.append(b"\n")
            elif m.lastgroup == "linebreak":  # type: ignore
                pass
            else:
                parts.append(m[0])
        if paren != 0:
            log.warning("Unterminated string at %d", pos)
            raise StopIteration
        return (self._curtokenpos, b"".join(parts))


# Stack slots may by occupied by any of:
#  * the name of a literal
#  * the PSBaseParserToken types
#  * list (via KEYWORD_ARRAY)
#  * dict (via KEYWORD_DICT)
#  * subclass-specific extensions (e.g. PDFStream, PDFObjRef) via ExtraT
ExtraT = TypeVar("ExtraT")
PSStackType = Union[str, float, bool, PSLiteral, bytes, List, Dict, ExtraT]
PSStackEntry = Tuple[int, PSStackType[ExtraT]]


class PSStackParser(Generic[ExtraT]):
    """Basic parser for PDF objects, can take a file or a `bytes` as
    input."""

    def __init__(self, reader: Union[BinaryIO, bytes]) -> None:
        self.reinit(reader)

    def reinit(self, reader: Union[BinaryIO, bytes]) -> None:
        """Reinitialize parser with a new file or buffer."""
        if isinstance(reader, bytes):
            self._parser: Union[PSInMemoryParser, PSFileParser] = PSInMemoryParser(
                reader
            )
        else:
            self._parser = PSFileParser(reader)
        self.reset()

    def reset(self) -> None:
        """Reset parser state."""
        self.context: List[Tuple[int, Optional[str], List[PSStackEntry[ExtraT]]]] = []
        self.curtype: Optional[str] = None
        self.curstack: List[PSStackEntry[ExtraT]] = []
        self.results: List[PSStackEntry[ExtraT]] = []

    def seek(self, pos: int) -> None:
        """Seek to a position and reset parser state."""
        self._parser.seek(pos)
        self.reset()

    def push(self, *objs: PSStackEntry[ExtraT]) -> None:
        """Push some objects onto the stack."""
        self.curstack.extend(objs)

    def pop(self, n: int) -> List[PSStackEntry[ExtraT]]:
        """Pop some objects off the stack."""
        objs = self.curstack[-n:]
        self.curstack[-n:] = []
        return objs

    def popall(self) -> List[PSStackEntry[ExtraT]]:
        """Pop all the things off the stack."""
        objs = self.curstack
        self.curstack = []
        return objs

    def add_results(self, *objs: PSStackEntry[ExtraT]) -> None:
        """Move some objects to the output."""
        try:
            log.debug("add_results: %r", objs)
        except Exception:
            log.debug("add_results: (unprintable object)")
        self.results.extend(objs)

    def start_type(self, pos: int, type: str) -> None:
        """Start a composite object (array, dict, etc)."""
        self.context.append((pos, self.curtype, self.curstack))
        (self.curtype, self.curstack) = (type, [])
        log.debug("start_type: pos=%r, type=%r", pos, type)

    def end_type(self, type: str) -> Tuple[int, List[PSStackType[ExtraT]]]:
        """End a composite object (array, dict, etc)."""
        if self.curtype != type:
            raise PSTypeError(f"Type mismatch: {self.curtype!r} != {type!r}")
        objs = [obj for (_, obj) in self.curstack]
        (pos, self.curtype, self.curstack) = self.context.pop()
        log.debug("end_type: pos=%r, type=%r, objs=%r", pos, type, objs)
        return (pos, objs)

    def do_keyword(self, pos: int, token: PSKeyword) -> None:
        """Handle a PDF keyword."""
        pass

    def flush(self) -> None:
        """Get everything off the stack and into the output?"""
        pass

    def nextobject(self) -> PSStackEntry[ExtraT]:
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
                self.start_type(pos, "a")
            elif token == KEYWORD_ARRAY_END:
                # end array
                try:
                    self.push(self.end_type("a"))
                except PSTypeError:
                    if settings.STRICT:
                        raise
            elif token == KEYWORD_DICT_BEGIN:
                # begin dictionary
                self.start_type(pos, "d")
            elif token == KEYWORD_DICT_END:
                # end dictionary
                try:
                    (pos, objs) = self.end_type("d")
                    if len(objs) % 2 != 0:
                        error_msg = "Invalid dictionary construct: %r" % objs
                        raise PSSyntaxError(error_msg)
                    d = {
                        literal_name(k): v
                        for (k, v) in choplist(2, objs)
                        if v is not None
                    }
                    self.push((pos, d))
                except PSTypeError:
                    if settings.STRICT:
                        raise
            elif token == KEYWORD_PROC_BEGIN:
                # begin proc
                self.start_type(pos, "p")
            elif token == KEYWORD_PROC_END:
                # end proc
                try:
                    self.push(self.end_type("p"))
                except PSTypeError:
                    if settings.STRICT:
                        raise
            elif isinstance(token, PSKeyword):
                log.debug(
                    "do_keyword: pos=%r, token=%r, stack=%r",
                    pos,
                    token,
                    self.curstack,
                )
                self.do_keyword(pos, token)
            else:
                log.error(
                    "unknown token: pos=%r, token=%r, stack=%r",
                    pos,
                    token,
                    self.curstack,
                )
                self.do_keyword(pos, token)
                raise PSException
            if self.context:
                continue
            else:
                self.flush()  # Does nothing here, but in subclasses... (ugh)
        obj = self.results.pop(0)
        try:
            log.debug("nextobject: %r", obj)
        except Exception:
            log.debug("nextobject: (unprintable object)")
        return obj

    # Delegation follows
    def nextline(self) -> Tuple[int, bytes]:
        r"""Fetches a next line that ends either with \r, \n, or
        \r\n."""
        return self._parser.nextline()

    def revreadlines(self) -> Iterator[bytes]:
        """Fetches a next line backwards.

        This is used to locate the trailers at the end of a file.
        """
        return self._parser.revreadlines()

    def read(self, pos: int, objlen: int) -> bytes:
        """Read data from a specified position, moving the current
        position to the end of this data."""
        return self._parser.read(pos, objlen)

    def nexttoken(self) -> Tuple[int, PSBaseParserToken]:
        """Get the next token in iteration, raising PSEOF when done."""
        try:
            return self.__next__()
        except StopIteration:
            raise PSEOF

    def get_inline_data(self, target: bytes = b"EI") -> Tuple[int, bytes]:
        """Get the data for an inline image up to the target
        end-of-stream marker."""
        return self._parser.get_inline_data(target)

    def __iter__(self) -> Iterator[Tuple[int, PSBaseParserToken]]:
        """Iterate over tokens."""
        return self

    def __next__(self) -> Tuple[int, PSBaseParserToken]:
        """Get the next token in iteration, raising StopIteration when
        done."""
        return self._parser.__next__()
