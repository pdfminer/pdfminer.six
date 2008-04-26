#!/usr/bin/env python
#
#  Arcfour implementation
#  * public domain *
#

class Arcfour:
  
  def __init__(self, key):
    s = range(256)
    j = 0
    klen = len(key)
    for i in xrange(256):
      j = (j + s[i] + ord(key[i % klen])) % 256
      (s[i], s[j]) = (s[j], s[i])
    self.s = s
    (self.i, self.j) = (0, 0)
    return

  def process(self, data):
    (i, j) = (self.i, self.j)
    s = self.s
    r = ''
    for c in data:
      i = (i+1) % 256
      j = (j+s[i]) % 256
      (s[i], s[j]) = (s[j], s[i])
      k = s[(s[i]+s[j]) % 256]
      r += chr(ord(c) ^ k)
    (self.i, self.j) = (i, j)
    return r

if __name__ == '__main__':
  def doit(key, data):
    cipher = Arcfour(key)
    return ''.join( '%02X' % ord(c) for c in cipher.process(data) )
  assert doit("Key", "Plaintext") == 'BBF316E8D940AF0AD3'
  assert doit("Wiki", "pedia") == '1021BF0420'
  assert doit("Secret", "Attack at dawn") == '45A01F645FC35B383552544B9BF5'
  print 'test succeeded'
