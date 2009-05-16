#!/usr/bin/env python
#
#  ASCII85/ASCIIHex decoder (Adobe version) implementation
#  * public domain *
#

# ascii85decode(data)
def ascii85decode(data):
  import struct
  n = b = 0
  out = ''
  for c in data:
    if '!' <= c and c <= 'u':
      n += 1
      b = b*85+(ord(c)-33)
      if n == 5:
        out += struct.pack('>L',b)
        n = b = 0
    elif c == 'z':
      assert n == 0
      out += '\0\0\0\0'
    elif c == '~':
      if n:
        for _ in range(5-n):
          b = b*85+84
        out += struct.pack('>L',b)[:n-1]
      break
  return out

# asciihexdecode(data)
def asciihexdecode(data):
  """
  ASCIIHexDecode filter: PDFReference v1.4 section 3.3.1
  For each pair of ASCII hexadecimal digits (0-9 and A-F or a-f), the
  ASCIIHexDecode filter produces one byte of binary data. All white-space
  characters are ignored. A right angle bracket character (>) indicates
  EOD. Any other characters will cause an error. If the filter encounters
  the EOD marker after reading an odd number of hexadecimal digits, it
  will behave as if a 0 followed the last digit.
  >>> asciihexdecode("61 62 2e6364   65")
  'ab.cde'
  >>> asciihexdecode("61 62 2e6364   657>")
  'ab.cdep'
  >>> asciihexdecode("7>")
  'p'
  """
  import re
  hex_re = re.compile(r'([a-f\d]{2})', re.IGNORECASE)
  trail_re = re.compile(r'^(?:[a-f\d]{2}|\s)*([a-f\d])[\s>]*$', re.IGNORECASE)
  decode = (lambda hx: chr(int(hx, 16)))
  out = map(decode, hex_re.findall(data))
  m = trail_re.search(data)
  if m:
    out.append(decode("%c0" % m.group(1)))
  return ''.join(out)


# test
# sample taken from: http://en.wikipedia.org/w/index.php?title=Ascii85
if __name__ == '__main__':
  orig = r'''
  9jqo^BlbD-BleB1DJ+*+F(f,q/0JhKF<GL>Cj@.4Gp$d7F!,L7@<6@)/0JDEF<G%<+EV:2F!,
  O<DJ+*.@<*K0@<6L(Df-\0Ec5e;DffZ(EZee.Bl.9pF"AGXBPCsi+DGm>@3BB/F*&OCAfu2/AKY
  i(DIb:@FD,*)+C]U=@3BN#EcYf8ATD3s@q?d$AftVqCh[NqF<G:8+EV:.+Cf>-FD5W8ARlolDIa
  l(DId<j@<?3r@:F%a+D58'ATD4$Bl@l3De:,-DJs`8ARoFb/0JMK@qB4^F!,R<AKZ&-DfTqBG%G
  >uD.RTpAKYo'+CT/5+Cei#DII?(E,9)oF*2M7/c~>
  '''
  data = \
       'Man is distinguished, not only by his reason, but by this singular passion from '\
       'other animals, which is a lust of the mind, that by a perseverance of delight in the '\
       'continued and indefatigable generation of knowledge, exceeds the short vehemence of '\
       'any carnal pleasure.'
  assert ascii85decode(orig) == data
  print 'ascii85decode test succeeded'

  import doctest
  doctest.testmod()
