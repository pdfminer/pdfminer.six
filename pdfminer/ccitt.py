
# CCITT Fax decoder
#
# Bugs: uncompressed mode untested.
#
#  cf.
#   ITU-T Recommendation T.4
#     "Standardization of Group 3 facsimile terminals for document transmission"
#   ITU-T Recommendation T.6
#     "FACSIMILE CODING SCHEMES AND CODING CONTROL FUNCTIONS FOR GROUP 4 FACSIMILE APPARATUS"


import sys
import array

import six  #Python 2+3 compatibility

if six.PY3:
    def get_bytes(data):
        for byte in data:
            yield byte
else:
    def get_bytes(data):
        for char in data:
            yield ord(char)


##  BitParser
##
class BitParser(object):

    def __init__(self):
        self._pos = 0
        return

    @classmethod
    def add(klass, root, v, bits):
        p = root
        b = None
        for i in range(len(bits)):
            if 0 < i:
                if p[b] is None:
                    p[b] = [None, None]
                p = p[b]
            if bits[i] == '1':
                b = 1
            else:
                b = 0
        p[b] = v
        return

    def feedbytes(self, data):
        for byte in get_bytes(data):
            for m in (128, 64, 32, 16, 8, 4, 2, 1):
                self._parse_bit(byte & m)
        return

    def _parse_bit(self, x):
        if x:
            v = self._state[1]
        else:
            v = self._state[0]
        self._pos += 1
        if isinstance(v, list):
            self._state = v
        else:
            self._state = self._accept(v)
        return


##  CCITTG4Parser
##
class CCITTG4Parser(BitParser):

    MODE = [None, None]
    BitParser.add(MODE, 0,   '1')
    BitParser.add(MODE, +1,  '011')
    BitParser.add(MODE, -1,  '010')
    BitParser.add(MODE, 'h', '001')
    BitParser.add(MODE, 'p', '0001')
    BitParser.add(MODE, +2,  '000011')
    BitParser.add(MODE, -2,  '000010')
    BitParser.add(MODE, +3,  '0000011')
    BitParser.add(MODE, -3,  '0000010')
    BitParser.add(MODE, 'u', '0000001111')
    BitParser.add(MODE, 'x1', '0000001000')
    BitParser.add(MODE, 'x2', '0000001001')
    BitParser.add(MODE, 'x3', '0000001010')
    BitParser.add(MODE, 'x4', '0000001011')
    BitParser.add(MODE, 'x5', '0000001100')
    BitParser.add(MODE, 'x6', '0000001101')
    BitParser.add(MODE, 'x7', '0000001110')
    BitParser.add(MODE, 'e', '000000000001000000000001')

    WHITE = [None, None]
    BitParser.add(WHITE, 0   , '00110101')
    BitParser.add(WHITE, 1   , '000111')
    BitParser.add(WHITE, 2   , '0111')
    BitParser.add(WHITE, 3   , '1000')
    BitParser.add(WHITE, 4   , '1011')
    BitParser.add(WHITE, 5   , '1100')
    BitParser.add(WHITE, 6   , '1110')
    BitParser.add(WHITE, 7   , '1111')
    BitParser.add(WHITE, 8   , '10011')
    BitParser.add(WHITE, 9   , '10100')
    BitParser.add(WHITE, 10  , '00111')
    BitParser.add(WHITE, 11  , '01000')
    BitParser.add(WHITE, 12  , '001000')
    BitParser.add(WHITE, 13  , '000011')
    BitParser.add(WHITE, 14  , '110100')
    BitParser.add(WHITE, 15  , '110101')
    BitParser.add(WHITE, 16  , '101010')
    BitParser.add(WHITE, 17  , '101011')
    BitParser.add(WHITE, 18  , '0100111')
    BitParser.add(WHITE, 19  , '0001100')
    BitParser.add(WHITE, 20  , '0001000')
    BitParser.add(WHITE, 21  , '0010111')
    BitParser.add(WHITE, 22  , '0000011')
    BitParser.add(WHITE, 23  , '0000100')
    BitParser.add(WHITE, 24  , '0101000')
    BitParser.add(WHITE, 25  , '0101011')
    BitParser.add(WHITE, 26  , '0010011')
    BitParser.add(WHITE, 27  , '0100100')
    BitParser.add(WHITE, 28  , '0011000')
    BitParser.add(WHITE, 29  , '00000010')
    BitParser.add(WHITE, 30  , '00000011')
    BitParser.add(WHITE, 31  , '00011010')
    BitParser.add(WHITE, 32  , '00011011')
    BitParser.add(WHITE, 33  , '00010010')
    BitParser.add(WHITE, 34  , '00010011')
    BitParser.add(WHITE, 35  , '00010100')
    BitParser.add(WHITE, 36  , '00010101')
    BitParser.add(WHITE, 37  , '00010110')
    BitParser.add(WHITE, 38  , '00010111')
    BitParser.add(WHITE, 39  , '00101000')
    BitParser.add(WHITE, 40  , '00101001')
    BitParser.add(WHITE, 41  , '00101010')
    BitParser.add(WHITE, 42  , '00101011')
    BitParser.add(WHITE, 43  , '00101100')
    BitParser.add(WHITE, 44  , '00101101')
    BitParser.add(WHITE, 45  , '00000100')
    BitParser.add(WHITE, 46  , '00000101')
    BitParser.add(WHITE, 47  , '00001010')
    BitParser.add(WHITE, 48  , '00001011')
    BitParser.add(WHITE, 49  , '01010010')
    BitParser.add(WHITE, 50  , '01010011')
    BitParser.add(WHITE, 51  , '01010100')
    BitParser.add(WHITE, 52  , '01010101')
    BitParser.add(WHITE, 53  , '00100100')
    BitParser.add(WHITE, 54  , '00100101')
    BitParser.add(WHITE, 55  , '01011000')
    BitParser.add(WHITE, 56  , '01011001')
    BitParser.add(WHITE, 57  , '01011010')
    BitParser.add(WHITE, 58  , '01011011')
    BitParser.add(WHITE, 59  , '01001010')
    BitParser.add(WHITE, 60  , '01001011')
    BitParser.add(WHITE, 61  , '00110010')
    BitParser.add(WHITE, 62  , '00110011')
    BitParser.add(WHITE, 63  , '00110100')
    BitParser.add(WHITE, 64  , '11011')
    BitParser.add(WHITE, 128 , '10010')
    BitParser.add(WHITE, 192 , '010111')
    BitParser.add(WHITE, 256 , '0110111')
    BitParser.add(WHITE, 320 , '00110110')
    BitParser.add(WHITE, 384 , '00110111')
    BitParser.add(WHITE, 448 , '01100100')
    BitParser.add(WHITE, 512 , '01100101')
    BitParser.add(WHITE, 576 , '01101000')
    BitParser.add(WHITE, 640 , '01100111')
    BitParser.add(WHITE, 704 , '011001100')
    BitParser.add(WHITE, 768 , '011001101')
    BitParser.add(WHITE, 832 , '011010010')
    BitParser.add(WHITE, 896 , '011010011')
    BitParser.add(WHITE, 960 , '011010100')
    BitParser.add(WHITE, 1024, '011010101')
    BitParser.add(WHITE, 1088, '011010110')
    BitParser.add(WHITE, 1152, '011010111')
    BitParser.add(WHITE, 1216, '011011000')
    BitParser.add(WHITE, 1280, '011011001')
    BitParser.add(WHITE, 1344, '011011010')
    BitParser.add(WHITE, 1408, '011011011')
    BitParser.add(WHITE, 1472, '010011000')
    BitParser.add(WHITE, 1536, '010011001')
    BitParser.add(WHITE, 1600, '010011010')
    BitParser.add(WHITE, 1664, '011000')
    BitParser.add(WHITE, 1728, '010011011')
    BitParser.add(WHITE, 1792, '00000001000')
    BitParser.add(WHITE, 1856, '00000001100')
    BitParser.add(WHITE, 1920, '00000001101')
    BitParser.add(WHITE, 1984, '000000010010')
    BitParser.add(WHITE, 2048, '000000010011')
    BitParser.add(WHITE, 2112, '000000010100')
    BitParser.add(WHITE, 2176, '000000010101')
    BitParser.add(WHITE, 2240, '000000010110')
    BitParser.add(WHITE, 2304, '000000010111')
    BitParser.add(WHITE, 2368, '000000011100')
    BitParser.add(WHITE, 2432, '000000011101')
    BitParser.add(WHITE, 2496, '000000011110')
    BitParser.add(WHITE, 2560, '000000011111')

    BLACK = [None, None]
    BitParser.add(BLACK, 0   , '0000110111')
    BitParser.add(BLACK, 1   , '010')
    BitParser.add(BLACK, 2   , '11')
    BitParser.add(BLACK, 3   , '10')
    BitParser.add(BLACK, 4   , '011')
    BitParser.add(BLACK, 5   , '0011')
    BitParser.add(BLACK, 6   , '0010')
    BitParser.add(BLACK, 7   , '00011')
    BitParser.add(BLACK, 8   , '000101')
    BitParser.add(BLACK, 9   , '000100')
    BitParser.add(BLACK, 10  , '0000100')
    BitParser.add(BLACK, 11  , '0000101')
    BitParser.add(BLACK, 12  , '0000111')
    BitParser.add(BLACK, 13  , '00000100')
    BitParser.add(BLACK, 14  , '00000111')
    BitParser.add(BLACK, 15  , '000011000')
    BitParser.add(BLACK, 16  , '0000010111')
    BitParser.add(BLACK, 17  , '0000011000')
    BitParser.add(BLACK, 18  , '0000001000')
    BitParser.add(BLACK, 19  , '00001100111')
    BitParser.add(BLACK, 20  , '00001101000')
    BitParser.add(BLACK, 21  , '00001101100')
    BitParser.add(BLACK, 22  , '00000110111')
    BitParser.add(BLACK, 23  , '00000101000')
    BitParser.add(BLACK, 24  , '00000010111')
    BitParser.add(BLACK, 25  , '00000011000')
    BitParser.add(BLACK, 26  , '000011001010')
    BitParser.add(BLACK, 27  , '000011001011')
    BitParser.add(BLACK, 28  , '000011001100')
    BitParser.add(BLACK, 29  , '000011001101')
    BitParser.add(BLACK, 30  , '000001101000')
    BitParser.add(BLACK, 31  , '000001101001')
    BitParser.add(BLACK, 32  , '000001101010')
    BitParser.add(BLACK, 33  , '000001101011')
    BitParser.add(BLACK, 34  , '000011010010')
    BitParser.add(BLACK, 35  , '000011010011')
    BitParser.add(BLACK, 36  , '000011010100')
    BitParser.add(BLACK, 37  , '000011010101')
    BitParser.add(BLACK, 38  , '000011010110')
    BitParser.add(BLACK, 39  , '000011010111')
    BitParser.add(BLACK, 40  , '000001101100')
    BitParser.add(BLACK, 41  , '000001101101')
    BitParser.add(BLACK, 42  , '000011011010')
    BitParser.add(BLACK, 43  , '000011011011')
    BitParser.add(BLACK, 44  , '000001010100')
    BitParser.add(BLACK, 45  , '000001010101')
    BitParser.add(BLACK, 46  , '000001010110')
    BitParser.add(BLACK, 47  , '000001010111')
    BitParser.add(BLACK, 48  , '000001100100')
    BitParser.add(BLACK, 49  , '000001100101')
    BitParser.add(BLACK, 50  , '000001010010')
    BitParser.add(BLACK, 51  , '000001010011')
    BitParser.add(BLACK, 52  , '000000100100')
    BitParser.add(BLACK, 53  , '000000110111')
    BitParser.add(BLACK, 54  , '000000111000')
    BitParser.add(BLACK, 55  , '000000100111')
    BitParser.add(BLACK, 56  , '000000101000')
    BitParser.add(BLACK, 57  , '000001011000')
    BitParser.add(BLACK, 58  , '000001011001')
    BitParser.add(BLACK, 59  , '000000101011')
    BitParser.add(BLACK, 60  , '000000101100')
    BitParser.add(BLACK, 61  , '000001011010')
    BitParser.add(BLACK, 62  , '000001100110')
    BitParser.add(BLACK, 63  , '000001100111')
    BitParser.add(BLACK, 64  , '0000001111')
    BitParser.add(BLACK, 128 , '000011001000')
    BitParser.add(BLACK, 192 , '000011001001')
    BitParser.add(BLACK, 256 , '000001011011')
    BitParser.add(BLACK, 320 , '000000110011')
    BitParser.add(BLACK, 384 , '000000110100')
    BitParser.add(BLACK, 448 , '000000110101')
    BitParser.add(BLACK, 512 , '0000001101100')
    BitParser.add(BLACK, 576 , '0000001101101')
    BitParser.add(BLACK, 640 , '0000001001010')
    BitParser.add(BLACK, 704 , '0000001001011')
    BitParser.add(BLACK, 768 , '0000001001100')
    BitParser.add(BLACK, 832 , '0000001001101')
    BitParser.add(BLACK, 896 , '0000001110010')
    BitParser.add(BLACK, 960 , '0000001110011')
    BitParser.add(BLACK, 1024, '0000001110100')
    BitParser.add(BLACK, 1088, '0000001110101')
    BitParser.add(BLACK, 1152, '0000001110110')
    BitParser.add(BLACK, 1216, '0000001110111')
    BitParser.add(BLACK, 1280, '0000001010010')
    BitParser.add(BLACK, 1344, '0000001010011')
    BitParser.add(BLACK, 1408, '0000001010100')
    BitParser.add(BLACK, 1472, '0000001010101')
    BitParser.add(BLACK, 1536, '0000001011010')
    BitParser.add(BLACK, 1600, '0000001011011')
    BitParser.add(BLACK, 1664, '0000001100100')
    BitParser.add(BLACK, 1728, '0000001100101')
    BitParser.add(BLACK, 1792, '00000001000')
    BitParser.add(BLACK, 1856, '00000001100')
    BitParser.add(BLACK, 1920, '00000001101')
    BitParser.add(BLACK, 1984, '000000010010')
    BitParser.add(BLACK, 2048, '000000010011')
    BitParser.add(BLACK, 2112, '000000010100')
    BitParser.add(BLACK, 2176, '000000010101')
    BitParser.add(BLACK, 2240, '000000010110')
    BitParser.add(BLACK, 2304, '000000010111')
    BitParser.add(BLACK, 2368, '000000011100')
    BitParser.add(BLACK, 2432, '000000011101')
    BitParser.add(BLACK, 2496, '000000011110')
    BitParser.add(BLACK, 2560, '000000011111')

    UNCOMPRESSED = [None, None]
    BitParser.add(UNCOMPRESSED, '1', '1')
    BitParser.add(UNCOMPRESSED, '01', '01')
    BitParser.add(UNCOMPRESSED, '001', '001')
    BitParser.add(UNCOMPRESSED, '0001', '0001')
    BitParser.add(UNCOMPRESSED, '00001', '00001')
    BitParser.add(UNCOMPRESSED, '00000', '000001')
    BitParser.add(UNCOMPRESSED, 'T00', '00000011')
    BitParser.add(UNCOMPRESSED, 'T10', '00000010')
    BitParser.add(UNCOMPRESSED, 'T000', '000000011')
    BitParser.add(UNCOMPRESSED, 'T100', '000000010')
    BitParser.add(UNCOMPRESSED, 'T0000', '0000000011')
    BitParser.add(UNCOMPRESSED, 'T1000', '0000000010')
    BitParser.add(UNCOMPRESSED, 'T00000', '00000000011')
    BitParser.add(UNCOMPRESSED, 'T10000', '00000000010')

    class EOFB(Exception):
        pass

    class InvalidData(Exception):
        pass

    class ByteSkip(Exception):
        pass

    def __init__(self, width, bytealign=False):
        BitParser.__init__(self)
        self.width = width
        self.bytealign = bytealign
        self.reset()
        return

    def feedbytes(self, data):
        for byte in get_bytes(data):
            try:
                for m in (128, 64, 32, 16, 8, 4, 2, 1):
                    self._parse_bit(byte & m)
            except self.ByteSkip:
                self._accept = self._parse_mode
                self._state = self.MODE
            except self.EOFB:
                break
        return

    def _parse_mode(self, mode):
        if mode == 'p':
            self._do_pass()
            self._flush_line()
            return self.MODE
        elif mode == 'h':
            self._n1 = 0
            self._accept = self._parse_horiz1
            if self._color:
                return self.WHITE
            else:
                return self.BLACK
        elif mode == 'u':
            self._accept = self._parse_uncompressed
            return self.UNCOMPRESSED
        elif mode == 'e':
            raise self.EOFB
        elif isinstance(mode, int):
            self._do_vertical(mode)
            self._flush_line()
            return self.MODE
        else:
            raise self.InvalidData(mode)

    def _parse_horiz1(self, n):
        if n is None:
            raise self.InvalidData
        self._n1 += n
        if n < 64:
            self._n2 = 0
            self._color = 1-self._color
            self._accept = self._parse_horiz2
        if self._color:
            return self.WHITE
        else:
            return self.BLACK

    def _parse_horiz2(self, n):
        if n is None:
            raise self.InvalidData
        self._n2 += n
        if n < 64:
            self._color = 1-self._color
            self._accept = self._parse_mode
            self._do_horizontal(self._n1, self._n2)
            self._flush_line()
            return self.MODE
        elif self._color:
            return self.WHITE
        else:
            return self.BLACK

    def _parse_uncompressed(self, bits):
        if not bits:
            raise self.InvalidData
        if bits.startswith('T'):
            self._accept = self._parse_mode
            self._color = int(bits[1])
            self._do_uncompressed(bits[2:])
            return self.MODE
        else:
            self._do_uncompressed(bits)
            return self.UNCOMPRESSED

    def _get_bits(self):
        return ''.join(str(b) for b in self._curline[:self._curpos])

    def _get_refline(self, i):
        if i < 0:
            return '[]'+''.join(str(b) for b in self._refline)
        elif len(self._refline) <= i:
            return ''.join(str(b) for b in self._refline)+'[]'
        else:
            return (''.join(str(b) for b in self._refline[:i]) +
                    '['+str(self._refline[i])+']' +
                    ''.join(str(b) for b in self._refline[i+1:]))

    def reset(self):
        self._y = 0
        self._curline = array.array('b', [1]*self.width)
        self._reset_line()
        self._accept = self._parse_mode
        self._state = self.MODE
        return

    def output_line(self, y, bits):
        print (y, ''.join(str(b) for b in bits))
        return

    def _reset_line(self):
        self._refline = self._curline
        self._curline = array.array('b', [1]*self.width)
        self._curpos = -1
        self._color = 1
        return

    def _flush_line(self):
        if self.width <= self._curpos:
            self.output_line(self._y, self._curline)
            self._y += 1
            self._reset_line()
            if self.bytealign:
                raise self.ByteSkip
        return

    def _do_vertical(self, dx):
        #print '* vertical(%d): curpos=%r, color=%r' % (dx, self._curpos, self._color)
        #print '  refline:', self._get_refline(self._curpos+1)
        x1 = self._curpos+1
        while 1:
            if x1 == 0:
                if (self._color == 1 and self._refline[x1] != self._color):
                    break
            elif x1 == len(self._refline):
                break
            elif (self._refline[x1-1] == self._color and
                  self._refline[x1] != self._color):
                break
            x1 += 1
        x1 += dx
        x0 = max(0, self._curpos)
        x1 = max(0, min(self.width, x1))
        if x1 < x0:
            for x in range(x1, x0):
                self._curline[x] = self._color
        elif x0 < x1:
            for x in range(x0, x1):
                self._curline[x] = self._color
        self._curpos = x1
        self._color = 1-self._color
        return

    def _do_pass(self):
        #print '* pass: curpos=%r, color=%r' % (self._curpos, self._color)
        #print '  refline:', self._get_refline(self._curpos+1)
        x1 = self._curpos+1
        while 1:
            if x1 == 0:
                if (self._color == 1 and self._refline[x1] != self._color):
                    break
            elif x1 == len(self._refline):
                break
            elif (self._refline[x1-1] == self._color and
                  self._refline[x1] != self._color):
                break
            x1 += 1
        while 1:
            if x1 == 0:
                if (self._color == 0 and self._refline[x1] == self._color):
                    break
            elif x1 == len(self._refline):
                break
            elif (self._refline[x1-1] != self._color and
                  self._refline[x1] == self._color):
                break
            x1 += 1
        for x in range(self._curpos, x1):
            self._curline[x] = self._color
        self._curpos = x1
        return

    def _do_horizontal(self, n1, n2):
        #print '* horizontal(%d,%d): curpos=%r, color=%r' % (n1, n2, self._curpos, self._color)
        if self._curpos < 0:
            self._curpos = 0
        x = self._curpos
        for _ in range(n1):
            if len(self._curline) <= x:
                break
            self._curline[x] = self._color
            x += 1
        for _ in range(n2):
            if len(self._curline) <= x:
                break
            self._curline[x] = 1-self._color
            x += 1
        self._curpos = x
        return

    def _do_uncompressed(self, bits):
        #print '* uncompressed(%r): curpos=%r' % (bits, self._curpos)
        for c in bits:
            self._curline[self._curpos] = int(c)
            self._curpos += 1
            self._flush_line()
        return




class CCITTFaxDecoder(CCITTG4Parser):

    def __init__(self, width, bytealign=False, reversed=False):
        CCITTG4Parser.__init__(self, width, bytealign=bytealign)
        self.reversed = reversed
        self._buf = b''
        return

    def close(self):
        return self._buf

    def output_line(self, y, bits):
        bytes = array.array('B', [0]*((len(bits)+7)//8))
        if self.reversed:
            bits = [1-b for b in bits]
        for (i, b) in enumerate(bits):
            if b:
                bytes[i//8] += (128, 64, 32, 16, 8, 4, 2, 1)[i % 8]
        self._buf += bytes.tostring()
        return


def ccittfaxdecode(data, params):
    K = params.get('K')
    cols = params.get('Columns')
    bytealign = params.get('EncodedByteAlign')
    reversed = params.get('BlackIs1')
    if K == -1:
        parser = CCITTFaxDecoder(cols, bytealign=bytealign, reversed=reversed)
    else:
        raise ValueError(K)
    parser.feedbytes(data)
    return parser.close()


# test
def main(argv):
    if not argv[1:]:
        return unittest.main()

    class Parser(CCITTG4Parser):
        def __init__(self, width, bytealign=False):
            import pygame
            CCITTG4Parser.__init__(self, width, bytealign=bytealign)
            self.img = pygame.Surface((self.width, 1000))
            return

        def output_line(self, y, bits):
            for (x, b) in enumerate(bits):
                if b:
                    self.img.set_at((x, y), (255, 255, 255))
                else:
                    self.img.set_at((x, y), (0, 0, 0))
            return

        def close(self):
            import pygame
            pygame.image.save(self.img, 'out.bmp')
            return
    for path in argv[1:]:
        fp = file(path, 'rb')
        (_, _, k, w, h, _) = path.split('.')
        parser = Parser(int(w))
        parser.feedbytes(fp.read())
        parser.close()
        fp.close()
    return

if __name__ == '__main__':
    sys.exit(main(sys.argv))
