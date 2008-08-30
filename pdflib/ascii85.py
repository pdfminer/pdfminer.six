#!/usr/bin/env python
#
#  ASCII85 decoder (Adobe version) implementation
#  * public domain *
#

import struct

# ascii85decode(data)
def ascii85decode(data):
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
  print 'test succeeded'
