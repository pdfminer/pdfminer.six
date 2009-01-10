#!/usr/bin/env python
from struct import unpack


##  Matrix operations
##
MATRIX_IDENTITY = (1, 0, 0, 1, 0, 0)

def mult_matrix((a1,b1,c1,d1,e1,f1), (a0,b0,c0,d0,e0,f0)):
  '''Multiplies two matrices.'''
  return (a0*a1+c0*b1,    b0*a1+d0*b1,
          a0*c1+c0*d1,    b0*c1+d0*d1,
          a0*e1+c0*f1+e0, b0*e1+d0*f1+f0)

def translate_matrix((a,b,c,d,e,f), (x,y)):
  return (a,b,c,d,e+x,f+y)
  
def apply_matrix((a,b,c,d,e,f), (x,y)):
  '''Applies a matrix to coordinates.'''
  return (a*x+c*y+e, b*x+d*y+f)

def apply_matrix_norm((a,b,c,d,e,f), (p,q)):
  '''equiv to apply_matrix(M, (p,q)) - apply_matrix(M, (0,0))'''
  return (a*p+c*q, b*p+d*q)


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
  '''Unpacks up to 4 bytes big endian.'''
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
