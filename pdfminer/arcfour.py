

""" Python implementation of Arcfour encryption algorithm.
See https://en.wikipedia.org/wiki/RC4
This code is in the public domain.

"""

import six # Python 2+3 compatibility
##  Arcfour
##
class Arcfour(object):

    def __init__(self, key):
        s = [i for i in range(256)] #because Py3 range is not indexable
        j = 0
        klen = len(key)
        for i in range(256):
            j = (j + s[i] + six.indexbytes(key,i % klen)) % 256
            (s[i], s[j]) = (s[j], s[i])
        self.s = s
        (self.i, self.j) = (0, 0)
        return

    def process(self, data):
        (i, j) = (self.i, self.j)
        s = self.s
        r = b''
        for c in six.iterbytes(data):
            i = (i+1) % 256
            j = (j+s[i]) % 256
            (s[i], s[j]) = (s[j], s[i])
            k = s[(s[i]+s[j]) % 256]
            r += six.int2byte(c ^ k)
        (self.i, self.j) = (i, j)
        return r
    
    encrypt = decrypt = process

new = Arcfour
