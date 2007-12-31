#!/usr/bin/env python
from struct import pack, unpack

##  Utilities
##
def choplist(n, seq):
  '''Groups every n elements of the list.'''
  r = []
  for x in seq:
    r.append(x)
    if len(r) == n:
      yield tuple(r)
      r = []
  return

def nunpack(s, default=0):
  '''Unpacks up to 4 bytes.'''
  l = len(s)
  if not l:
    return default
  elif l == 1:
    return ord(s)
  elif l == 2:
    return unpack('>H', s)[0]
  elif l == 3:
    return unpack('>L', '\x00'+s)[0]
  elif l == 4:
    return unpack('>L', s)[0]
  else:
    return TypeError('invalid length: %d' % l)
