#!/usr/bin/env python
import sys
INF = sys.maxint


##  Rect
##
class Rect:
  
  def __init__(self, x=-INF, y=-INF, width=None, height=None):
    self.x0 = x
    self.y0 = y
    if width == None:
      self.x1 = INF
    else:      
      self.x1 = x+width
    if height == None:
      self.y1 = INF
    else:
      self.y1 = y+height
    return

  def __repr__(self):
    return '<Rect: (%d,%d) (%dx%d)>' % (self.x0, self.y0, self.x1-self.x0, self.y1-self.y0)

  def overlap(self, rect):
    return not (rect.x1 <= self.x0 or self.x1 <= rect.x0 or
                rect.y1 <= self.y0 or self.y1 <= rect.y0)


##  ExtGrid
##
class ExtGrid:
  
  def __init__(self, gridsize):
    self.gridsize = gridsize
    self.gridy = {}
    return

  def __repr__(self):
    return '<ExtGrid(size=%d): %r>' % (self.gridsize, self.gridy)
  
  def cells(self, x0, x1):
    i = int(x0 / self.gridsize)
    x = i * self.gridsize
    while x < x1:
      yield i
      x += self.gridsize
      i += 1
    return
  
  def add(self, rect, obj):
    if isinstance(rect, tuple): rect = Rect(*rect)
    xcells = list(self.cells(rect.x0, rect.x1))
    for y in self.cells(rect.y0, rect.y1):
      if y not in self.gridy:
        gridx = {}
        self.gridy[y] = gridx
      else:
        gridx = self.gridy[y]
      for x in xcells:
        assert isinstance(gridx, dict), gridx
        if x not in gridx:
          objs = []
          gridx[x] = objs
        else:
          objs = gridx[x]
        objs.append((rect, obj))
        assert isinstance(gridx, dict), gridx
    return
  
  def get(self, rect):
    if isinstance(rect, tuple): rect = Rect(*rect)
    objs = set()
    xcells = list(self.cells(rect.x0, rect.x1))
    for y in self.cells(rect.y0, rect.y1):
      if y not in self.gridy: continue
      gridx = self.gridy[y]
      for x in xcells:
        if x not in gridx: continue
        objs.update( obj for (r,obj) in gridx[x] if rect.overlap(r) )
    return objs


if __name__ == '__main__':
  e = ExtGrid(10)
  assert list(e.cells(-1, 1)) == [-1,0]
  assert list(e.cells(0, 1)) == [0]
  assert list(e.cells(0, 10)) == [0]
  assert list(e.cells(0, 11)) == [0,1]
  assert list(e.cells(1, 11)) == [0,1]
  assert list(e.cells(10, 11)) == [1]
  assert list(e.cells(0, 20)) == [0,1]
  assert list(e.cells(10, 20)) == [1]
  assert list(e.cells(1,21)) == [0,1,2]
  assert list(e.cells(11,21)) == [1,2]
  e.add((0,0,10,10), 'a')
  e.add((10,10,10,10), 'b')
  e.add((5,5,5,10), 'c')
  assert sorted(e.get((0,0,1,1))) == ['a']
  assert sorted(e.get((10,10,1,1))) == ['b']
  assert sorted(e.get((5,10,10,10))) == ['b','c']
  assert sorted(e.get((5,5,10,10))) == ['a','b','c']
