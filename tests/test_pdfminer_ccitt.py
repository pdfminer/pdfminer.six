from pdfminer.ccitt import CCITTG4Parser, CCITTFaxDecoder


class TestCCITTG4Parser():
    def get_parser(self, bits):
        parser = CCITTG4Parser(len(bits))
        parser._curline = [int(c) for c in bits]
        parser._reset_line()
        return parser

    def test_b1(self):
        parser = self.get_parser('00000')
        parser._do_vertical(0)
        assert parser._curpos == 0
        return

    def test_b2(self):
        parser = self.get_parser('10000')
        parser._do_vertical(-1)
        assert parser._curpos == 0
        return

    def test_b3(self):
        parser = self.get_parser('000111')
        parser._do_pass()
        assert parser._curpos == 3
        assert parser._get_bits() == '111'
        return

    def test_b4(self):
        parser = self.get_parser('00000')
        parser._do_vertical(+2)
        assert parser._curpos == 2
        assert parser._get_bits() == '11'
        return

    def test_b5(self):
        parser = self.get_parser('11111111100')
        parser._do_horizontal(0, 3)
        assert parser._curpos == 3
        parser._do_vertical(1)
        assert parser._curpos == 10
        assert parser._get_bits() == '0001111111'
        return

    def test_e1(self):
        parser = self.get_parser('10000')
        parser._do_vertical(0)
        assert parser._curpos == 1
        parser._do_vertical(0)
        assert parser._curpos == 5
        assert parser._get_bits() == '10000'
        return

    def test_e2(self):
        parser = self.get_parser('10011')
        parser._do_vertical(0)
        assert parser._curpos == 1
        parser._do_vertical(2)
        assert parser._curpos == 5
        assert parser._get_bits() == '10000'
        return

    def test_e3(self):
        parser = self.get_parser('011111')
        parser._color = 0
        parser._do_vertical(0)
        assert parser._color == 1
        assert parser._curpos == 1
        parser._do_vertical(-2)
        assert parser._color == 0
        assert parser._curpos == 4
        parser._do_vertical(0)
        assert parser._curpos == 6
        assert parser._get_bits() == '011100'
        return

    def test_e4(self):
        parser = self.get_parser('10000')
        parser._do_vertical(0)
        assert parser._curpos == 1
        parser._do_vertical(-2)
        assert parser._curpos == 3
        parser._do_vertical(0)
        assert parser._curpos == 5
        assert parser._get_bits() == '10011'
        return

    def test_e5(self):
        parser = self.get_parser('011000')
        parser._color = 0
        parser._do_vertical(0)
        assert parser._curpos == 1
        parser._do_vertical(3)
        assert parser._curpos == 6
        assert parser._get_bits() == '011111'
        return

    def test_e6(self):
        parser = self.get_parser('11001')
        parser._do_pass()
        assert parser._curpos == 4
        parser._do_vertical(0)
        assert parser._curpos == 5
        assert parser._get_bits() == '11111'
        return

    def test_e7(self):
        parser = self.get_parser('0000000000')
        parser._curpos = 2
        parser._color = 1
        parser._do_horizontal(2, 6)
        assert parser._curpos == 10
        assert parser._get_bits() == '1111000000'
        return

    def test_e8(self):
        parser = self.get_parser('001100000')
        parser._curpos = 1
        parser._color = 0
        parser._do_vertical(0)
        assert parser._curpos == 2
        parser._do_horizontal(7, 0)
        assert parser._curpos == 9
        assert parser._get_bits() == '101111111'
        return

    def test_m1(self):
        parser = self.get_parser('10101')
        parser._do_pass()
        assert parser._curpos == 2
        parser._do_pass()
        assert parser._curpos == 4
        assert parser._get_bits() == '1111'
        return

    def test_m2(self):
        parser = self.get_parser('101011')
        parser._do_vertical(-1)
        parser._do_vertical(-1)
        parser._do_vertical(1)
        parser._do_horizontal(1, 1)
        assert parser._get_bits() == '011101'
        return

    def test_m3(self):
        parser = self.get_parser('10111011')
        parser._do_vertical(-1)
        parser._do_pass()
        parser._do_vertical(1)
        parser._do_vertical(1)
        assert parser._get_bits() == '00000001'
        return


class TestCCITTFaxDecoder:
    def test_b1(self):
        decoder = CCITTFaxDecoder(5)
        decoder.output_line(0, b'0')
        assert decoder.close() == b'\x80'
        return
