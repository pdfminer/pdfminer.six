import logging
from io import BytesIO

from pdfminer.psexceptions import PSEOF
from pdfminer.psparser import KWD, LIT, PSBaseParser, PSStackParser

logger = logging.getLogger(__name__)


class TestPSBaseParser:
    """Simplistic Test cases"""

    TESTDATA = rb"""%!PS
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
<> <20> < 40 4020 >
<abcd00
12345>
func/a/b{(c)do*}def
[ 1 (z) ! ]
<< /foo (bar) >>
"""

    TOKENS = [
        (5, KWD(b"begin")),
        (11, KWD(b"end")),
        (16, KWD(b'"')),
        (19, KWD(b"@")),
        (21, KWD(b"#")),
        (23, LIT("a")),
        (25, LIT("BCD")),
        (30, LIT("Some_Name")),
        (41, LIT("foo_xbaa")),
        (54, 0),
        (56, 1),
        (59, -2),
        (62, 0.5),
        (65, 1.234),
        (71, b"abc"),
        (77, b""),
        (80, b"abc ( def ) ghi"),
        (98, b"def \x00 4ghi"),
        (118, b"bach\\slask"),
        (132, b"foo\nbaa"),
        (143, b"this % is not a comment."),
        (170, b"foo\nbaa"),
        (180, b"foobaa"),
        (191, b""),
        (194, b" "),
        (199, b"@@ "),
        (211, b"\xab\xcd\x00\x124\x05"),
        (226, KWD(b"func")),
        (230, LIT("a")),
        (232, LIT("b")),
        (234, KWD(b"{")),
        (235, b"c"),
        (238, KWD(b"do*")),
        (241, KWD(b"}")),
        (242, KWD(b"def")),
        (246, KWD(b"[")),
        (248, 1),
        (250, b"z"),
        (254, KWD(b"!")),
        (256, KWD(b"]")),
        (258, KWD(b"<<")),
        (261, LIT("foo")),
        (266, b"bar"),
        (272, KWD(b">>")),
    ]

    OBJS = [
        (23, LIT("a")),
        (25, LIT("BCD")),
        (30, LIT("Some_Name")),
        (41, LIT("foo_xbaa")),
        (54, 0),
        (56, 1),
        (59, -2),
        (62, 0.5),
        (65, 1.234),
        (71, b"abc"),
        (77, b""),
        (80, b"abc ( def ) ghi"),
        (98, b"def \x00 4ghi"),
        (118, b"bach\\slask"),
        (132, b"foo\nbaa"),
        (143, b"this % is not a comment."),
        (170, b"foo\nbaa"),
        (180, b"foobaa"),
        (191, b""),
        (194, b" "),
        (199, b"@@ "),
        (211, b"\xab\xcd\x00\x124\x05"),
        (230, LIT("a")),
        (232, LIT("b")),
        (234, [b"c"]),
        (246, [1, b"z"]),
        (258, {"foo": b"bar"}),
    ]

    def get_tokens(self, s):
        from io import BytesIO

        class MyParser(PSBaseParser):
            def flush(self):
                self.add_results(*self.popall())

        parser = MyParser(BytesIO(s))
        r = []
        try:
            while True:
                r.append(parser.nexttoken())
        except PSEOF:
            pass
        return r

    def get_objects(self, s):
        from io import BytesIO

        class MyParser(PSStackParser):
            def flush(self):
                self.add_results(*self.popall())

        parser = MyParser(BytesIO(s))
        r = []
        try:
            while True:
                r.append(parser.nextobject())
        except PSEOF:
            pass
        return r

    def test_1(self):
        tokens = self.get_tokens(self.TESTDATA)
        logger.info(tokens)
        assert tokens == self.TOKENS

    def test_2(self):
        objs = self.get_objects(self.TESTDATA)
        logger.info(objs)
        assert objs == self.OBJS

    def test_3(self):
        """Regression test for streams that end with a keyword.

        See: https://github.com/pdfminer/pdfminer.six/issues/884
        """
        parser = PSBaseParser(BytesIO(b"Do"))
        pos, token = parser.nexttoken()
        assert token == KWD(b"Do")


# Add extra spaces to put "beginbfchar" across a 4096-byte boundary
BIGDATA = (
    (b" " * 218)
    + b"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo
3 dict dup begin
/Registry (Adobe) def
/Ordering (SI-*Times New Roman-4498) def
/Supplement 0 def
end def
/CMapName /Adobe-SI-*Times New Roman-4498-0 def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
100 beginbfchar
<0000> <FFFD>
<0001> <006F>
<0002> <0065>
<0003> <0073>
<0004> <006E>
<0005> <003A>
<0006> <0065>
<0007> <0069>
<0008> <0069>
<0009> <006C>
<000A> <006C>
<000B> <006E>
<000C> <006E0067>
<000D> <002E>
<000E> <0054>
<000F> <0064>
<0010> <006E0067>
<0011> <003A>
<0012> <0048>
<0013> <0050>
<0014> <0062>
<0015> <0063>
<0016> <0065>
<0017> <0067>
<0018> <0067>
<0019> <0069>
<001A> <0069>
<001B> <006C>
<001C> <006E>
<001D> <0072>
<001E> <0072>
<001F> <0074>
<0020> <0022>
<0021> <0028002C004C002900650074>
<0022> <002B006C003A002E>
<0023> <002D006C00720022>
<0024> <002D006C00720022>
<0025> <002D006E>
<0026> <002D0072006F>
<0027> <002D0074006C>
<0028> <002E>
<0029> <002E>
<002A> <002E>
<002B> <002E>
<002C> <002E>
<002D> <0036006F002E00530074006C>
<002E> <0039>
<002F> <003A>
<0030> <003A>
<0031> <003A>
<0032> <003A>
<0033> <003A0029>
<0034> <003A002C>
<0035> <003A002C>
<0036> <0043002E004F002E002E002E>
<0037> <0044002E0043004B>
<0038> <00440065006F002E004A>
<0039> <00440075006E>
<003A> <0046>
<003B> <0046006F>
<003C> <0046006F004A>
<003D> <0046006F0068004B006F0069>
<003E> <0046006F0072>
<003F> <0049>
<0040> <004A>
<0041> <004B>
<0042> <004B>
<0043> <004B>
<0044> <004D>
<0045> <004D005F0039>
<0046> <0050>
<0047> <0050>
<0048> <0050>
<0049> <0052>
<004A> <0053>
<004B> <0053>
<004C> <00530074>
<004D> <0054>
<004E> <0054006F>
<004F> <005C>
<0050> <00610072>
<0051> <0062>
<0052> <0062>
<0053> <0063>
<0054> <0063>
<0055> <0063002E>
<0056> <0063002E>
<0057> <00630065>
<0058> <006300650064002E>
<0059> <006300650064002E>
<005A> <00630069>
<005B> <00630074>
<005C> <00630075>
<005D> <0064>
<005E> <0064>
<005F> <0064>
<0060> <0064003A002C>
<0061> <00640069>
<0062> <0065>
<0063> <0065>
endbfchar
100 beginbfchar
<0064> <0065>
<0065> <0065002C>
<0066> <0065002C0065006F002E002E>
<0067> <0065006F002E002E>
<0068> <00650070006F>
<0069> <00650072>
<006A> <00650072>
<006B> <00650074>
<006C> <00660075>
<006D> <006600750065>
<006E> <0067>
<006F> <0068>
<0070> <0068>
<0071> <0068>
<0072> <0068005F003A0029>
<0073> <00680065>
<0074> <00680065006F002E0064>
<0075> <0068006F0063002E004B>
<0076> <0069>
<0077> <0069>
<0078> <0069>
<0079> <0069>
<007A> <0069>
<007B> <0069>
<007C> <0069>
<007D> <0069>
<007E> <0069006F>
<007F> <0069006F002E002E>
<0080> <00690074>
<0081> <006C>
<0082> <006C>
<0083> <006C>
<0084> <006C0065>
<0085> <006D>
<0086> <006D>
<0087> <006D>
<0088> <006D00610072>
<0089> <006D00650074>
<008A> <006E>
<008B> <006E>
<008C> <006E002E>
<008D> <006E005F0039>
<008E> <006E0065>
<008F> <006E006B003C003E>
<0090> <006E006F002E0064002E>
<0091> <006E00730074>
<0092> <006F>
<0093> <006F>
<0094> <006F>
<0095> <006F>
<0096> <006F>
<0097> <006F>
<0098> <006F>
<0099> <006F002E002E>
<009A> <006F002E002E>
<009B> <006F002E002E>
<009C> <006F002E0064>
<009D> <006F002E0065>
<009E> <006F002E006E>
<009F> <006F002E006E>
<00A0> <006F002E006E>
<00A1> <006F002E006E0074>
<00A2> <006F002E006E00750073>
<00A3> <006F002E0070>
<00A4> <006F002E0072>
<00A5> <006F002E0072>
<00A6> <006F002E00720072>
<00A7> <006F002E0077>
<00A8> <006F004A>
<00A9> <006F004A>
<00AA> <006F004A>
<00AB> <006F0064>
<00AC> <006F0065>
<00AD> <006F006C>
<00AE> <006F0073>
<00AF> <006F0073>
<00B0> <006F0074>
<00B1> <006F00A5>
<00B2> <006F00A5>
<00B3> <0070>
<00B4> <0070>
<00B5> <0070003C003E>
<00B6> <0070003C003E>
<00B7> <00700065>
<00B8> <00700072>
<00B9> <0072>
<00BA> <0072>
<00BB> <0072>
<00BC> <0072>
<00BD> <0072>
<00BE> <0072>
<00BF> <0072>
<00C0> <0072>
<00C1> <0072>
<00C2> <0072>
<00C3> <0072>
<00C4> <0072>
<00C5> <007200270039>
<00C6> <0072002E>
<00C7> <0072005C>
endbfchar
49 beginbfchar
<00C8> <0072006F0064>
<00C9> <00720072006D>
<00CA> <00720072006D0065>
<00CB> <007200740068>
<00CC> <00720075>
<00CD> <0072007A006F>
<00CE> <0073>
<00CF> <0073>
<00D0> <0073>
<00D1> <0073>
<00D2> <0073002E>
<00D3> <00730065>
<00D4> <00730065>
<00D5> <0073006F>
<00D6> <007300750062>
<00D7> <007300750062>
<00D8> <0074>
<00D9> <0074>
<00DA> <0074>
<00DB> <0074>
<00DC> <0074>
<00DD> <0074005C>
<00DE> <007400680065>
<00DF> <0074006D0065006E0074>
<00E0> <0074006F>
<00E1> <00740072>
<00E2> <00740074>
<00E3> <0075>
<00E4> <0075006E>
<00E5> <0075006E0064>
<00E6> <0076>
<00E7> <0076>
<00E8> <0076>
<00E9> <0077>
<00EA> <0077>
<00EB> <00770068006F>
<00EC> <0077006F002E002E>
<00ED> <0077006F002E00B10065>
<00EE> <0078>
<00EF> <00A5>
<00F0> <00B00027003B0039>
<00F1> <FFFD>
<00F2> <FFFD>
<00F3> <FFFD>
<00F4> <0020>
<00F5> <0009>
<00F6> <000A>
<00F7> <00A0>
<00F8> <00AD>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end"""
)
# as a bonus, omit the final CRLF so that we can verify that we don't
# re-break #884


def test_issue_1025():
    """Regression test for streams with a token that crosses a
    buffer boundary.

    See: https://github.com/pdfminer/pdfminer.six/issues/1025
    """
    parser = PSBaseParser(BytesIO(BIGDATA))
    beginbfchar = KWD(b"beginbfchar")
    end = KWD(b"end")
    tokens = []
    while True:
        try:
            pos, token = parser.nexttoken()
            tokens.append(token)
        except PSEOF:
            break
    # we should get "beginbfchar" 3 times (including the broken one)
    assert sum(1 for token in tokens if token is beginbfchar) == 3
    # we should get both "end" at the end
    assert tokens[-1] == end
    assert tokens[-2] == tokens[-1]
