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


BIGDATA = b"""/CIDInit /ProcSet findresource begin\r
12 dict begin\r
begincmap\r
/CIDSystemInfo\r
3 dict dup begin\r
/Registry (Adobe) def\r
/Ordering (SI-*Times New Roman-4498) def\r
/Supplement 0 def\r
end def\r
/CMapName /Adobe-SI-*Times New Roman-4498-0 def\r
/CMapType 2 def\r
1 begincodespacerange\r
<0000> <FFFF>\r
endcodespacerange\r
100 beginbfchar\r
<0000> <FFFD>\r
<0001> <006F>\r
<0002> <0065>\r
<0003> <0073>\r
<0004> <006E>\r
<0005> <003A>\r
<0006> <0065>\r
<0007> <0069>\r
<0008> <0069>\r
<0009> <006C>\r
<000A> <006C>\r
<000B> <006E>\r
<000C> <006E0067>\r
<000D> <002E>\r
<000E> <0054>\r
<000F> <0064>\r
<0010> <006E0067>\r
<0011> <003A>\r
<0012> <0048>\r
<0013> <0050>\r
<0014> <0062>\r
<0015> <0063>\r
<0016> <0065>\r
<0017> <0067>\r
<0018> <0067>\r
<0019> <0069>\r
<001A> <0069>\r
<001B> <006C>\r
<001C> <006E>\r
<001D> <0072>\r
<001E> <0072>\r
<001F> <0074>\r
<0020> <0022>\r
<0021> <0028002C004C002900650074>\r
<0022> <002B006C003A002E>\r
<0023> <002D006C00720022>\r
<0024> <002D006C00720022>\r
<0025> <002D006E>\r
<0026> <002D0072006F>\r
<0027> <002D0074006C>\r
<0028> <002E>\r
<0029> <002E>\r
<002A> <002E>\r
<002B> <002E>\r
<002C> <002E>\r
<002D> <0036006F002E00530074006C>\r
<002E> <0039>\r
<002F> <003A>\r
<0030> <003A>\r
<0031> <003A>\r
<0032> <003A>\r
<0033> <003A0029>\r
<0034> <003A002C>\r
<0035> <003A002C>\r
<0036> <0043002E004F002E002E002E>\r
<0037> <0044002E0043004B>\r
<0038> <00440065006F002E004A>\r
<0039> <00440075006E>\r
<003A> <0046>\r
<003B> <0046006F>\r
<003C> <0046006F004A>\r
<003D> <0046006F0068004B006F0069>\r
<003E> <0046006F0072>\r
<003F> <0049>\r
<0040> <004A>\r
<0041> <004B>\r
<0042> <004B>\r
<0043> <004B>\r
<0044> <004D>\r
<0045> <004D005F0039>\r
<0046> <0050>\r
<0047> <0050>\r
<0048> <0050>\r
<0049> <0052>\r
<004A> <0053>\r
<004B> <0053>\r
<004C> <00530074>\r
<004D> <0054>\r
<004E> <0054006F>\r
<004F> <005C>\r
<0050> <00610072>\r
<0051> <0062>\r
<0052> <0062>\r
<0053> <0063>\r
<0054> <0063>\r
<0055> <0063002E>\r
<0056> <0063002E>\r
<0057> <00630065>\r
<0058> <006300650064002E>\r
<0059> <006300650064002E>\r
<005A> <00630069>\r
<005B> <00630074>\r
<005C> <00630075>\r
<005D> <0064>\r
<005E> <0064>\r
<005F> <0064>\r
<0060> <0064003A002C>\r
<0061> <00640069>\r
<0062> <0065>\r
<0063> <0065>\r
endbfchar\r
100 beginbfchar\r
<0064> <0065>\r
<0065> <0065002C>\r
<0066> <0065002C0065006F002E002E>\r
<0067> <0065006F002E002E>\r
<0068> <00650070006F>\r
<0069> <00650072>\r
<006A> <00650072>\r
<006B> <00650074>\r
<006C> <00660075>\r
<006D> <006600750065>\r
<006E> <0067>\r
<006F> <0068>\r
<0070> <0068>\r
<0071> <0068>\r
<0072> <0068005F003A0029>\r
<0073> <00680065>\r
<0074> <00680065006F002E0064>\r
<0075> <0068006F0063002E004B>\r
<0076> <0069>\r
<0077> <0069>\r
<0078> <0069>\r
<0079> <0069>\r
<007A> <0069>\r
<007B> <0069>\r
<007C> <0069>\r
<007D> <0069>\r
<007E> <0069006F>\r
<007F> <0069006F002E002E>\r
<0080> <00690074>\r
<0081> <006C>\r
<0082> <006C>\r
<0083> <006C>\r
<0084> <006C0065>\r
<0085> <006D>\r
<0086> <006D>\r
<0087> <006D>\r
<0088> <006D00610072>\r
<0089> <006D00650074>\r
<008A> <006E>\r
<008B> <006E>\r
<008C> <006E002E>\r
<008D> <006E005F0039>\r
<008E> <006E0065>\r
<008F> <006E006B003C003E>\r
<0090> <006E006F002E0064002E>\r
<0091> <006E00730074>\r
<0092> <006F>\r
<0093> <006F>\r
<0094> <006F>\r
<0095> <006F>\r
<0096> <006F>\r
<0097> <006F>\r
<0098> <006F>\r
<0099> <006F002E002E>\r
<009A> <006F002E002E>\r
<009B> <006F002E002E>\r
<009C> <006F002E0064>\r
<009D> <006F002E0065>\r
<009E> <006F002E006E>\r
<009F> <006F002E006E>\r
<00A0> <006F002E006E>\r
<00A1> <006F002E006E0074>\r
<00A2> <006F002E006E00750073>\r
<00A3> <006F002E0070>\r
<00A4> <006F002E0072>\r
<00A5> <006F002E0072>\r
<00A6> <006F002E00720072>\r
<00A7> <006F002E0077>\r
<00A8> <006F004A>\r
<00A9> <006F004A>\r
<00AA> <006F004A>\r
<00AB> <006F0064>\r
<00AC> <006F0065>\r
<00AD> <006F006C>\r
<00AE> <006F0073>\r
<00AF> <006F0073>\r
<00B0> <006F0074>\r
<00B1> <006F00A5>\r
<00B2> <006F00A5>\r
<00B3> <0070>\r
<00B4> <0070>\r
<00B5> <0070003C003E>\r
<00B6> <0070003C003E>\r
<00B7> <00700065>\r
<00B8> <00700072>\r
<00B9> <0072>\r
<00BA> <0072>\r
<00BB> <0072>\r
<00BC> <0072>\r
<00BD> <0072>\r
<00BE> <0072>\r
<00BF> <0072>\r
<00C0> <0072>\r
<00C1> <0072>\r
<00C2> <0072>\r
<00C3> <0072>\r
<00C4> <0072>\r
<00C5> <007200270039>\r
<00C6> <0072002E>\r
<00C7> <0072005C>\r
endbfchar\r
49 beginbfchar\r
<00C8> <0072006F0064>\r
<00C9> <00720072006D>\r
<00CA> <00720072006D0065>\r
<00CB> <007200740068>\r
<00CC> <00720075>\r
<00CD> <0072007A006F>\r
<00CE> <0073>\r
<00CF> <0073>\r
<00D0> <0073>\r
<00D1> <0073>\r
<00D2> <0073002E>\r
<00D3> <00730065>\r
<00D4> <00730065>\r
<00D5> <0073006F>\r
<00D6> <007300750062>\r
<00D7> <007300750062>\r
<00D8> <0074>\r
<00D9> <0074>\r
<00DA> <0074>\r
<00DB> <0074>\r
<00DC> <0074>\r
<00DD> <0074005C>\r
<00DE> <007400680065>\r
<00DF> <0074006D0065006E0074>\r
<00E0> <0074006F>\r
<00E1> <00740072>\r
<00E2> <00740074>\r
<00E3> <0075>\r
<00E4> <0075006E>\r
<00E5> <0075006E0064>\r
<00E6> <0076>\r
<00E7> <0076>\r
<00E8> <0076>\r
<00E9> <0077>\r
<00EA> <0077>\r
<00EB> <00770068006F>\r
<00EC> <0077006F002E002E>\r
<00ED> <0077006F002E00B10065>\r
<00EE> <0078>\r
<00EF> <00A5>\r
<00F0> <00B00027003B0039>\r
<00F1> <FFFD>\r
<00F2> <FFFD>\r
<00F3> <FFFD>\r
<00F4> <0020>\r
<00F5> <0009>\r
<00F6> <000A>\r
<00F7> <00A0>\r
<00F8> <00AD>\r
endbfchar\r
endcmap\r
CMapName currentdict /CMap defineresource pop\r
end\r
end"""
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
            # Make sure we are really testing the problem!
            if pos == 4093:
                assert token is beginbfchar
            tokens.append(token)
        except PSEOF:
            break
    # we should get "beginbfchar" 3 times (including the broken one)
    assert sum(1 for token in tokens if token is beginbfchar) == 3
    # we should get both "end" at the end
    assert tokens[-1] == end
    assert tokens[-2] == tokens[-1]
