#!/usr/bin/env python
import sys
from utils import matrix2str, rect2str, point2str, pick, apply_matrix_norm
INF = sys.maxint


##  PageItem
##
class PageItem(object):

  def __init__(self, (x0,y0,x1,y1)):
    #assert x0 <= x1 and y0 <= y1
    self.x0 = x0
    self.y0 = y0
    self.x1 = x1
    self.y1 = y1
    self.width = x1-x0
    self.height = y1-y0
    return

  def __repr__(self):
    return ('<pageitem bbox=%s>' % (self.bbox()))
  
  def bbox(self):
    return rect2str((self.x0, self.y0, self.x1, self.y1))
  
  def hoverlap(self, obj):
    assert isinstance(obj, PageItem)
    if self.x1 <= obj.x0 or obj.x1 <= self.x0:
      return 0
    else:
      return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))

  def voverlap(self, obj):
    assert isinstance(obj, PageItem)
    if self.y1 <= obj.y0 or obj.y1 <= self.y0:
      return 0
    else:
      return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))
  
  
class PageContainer(PageItem):
  
  def __init__(self, bbox):
    PageItem.__init__(self, bbox)
    self.objs = []
    return
  
  def add(self, obj):
    self.objs.append(obj)
    return
  
class Page(PageContainer):
  
  def __init__(self, id, bbox, rotate=0):
    PageContainer.__init__(self, bbox)
    self.id = id
    self.rotate = rotate
    return
  
  def __repr__(self):
    return ('<page id=%r bbox=%s rotate=%r>' % (self.id, self.bbox(), self.rotate))


##  FigureItem
##
class FigureItem(PageContainer):
  
  def __init__(self, id, bbox):
    PageContainer.__init__(self, bbox)
    self.id = id
    return
  
  def __repr__(self):
    return ('<figure id=%r bbox=%s>' % (self.id, self.bbox()))
  

##  TextItem
##
class TextItem(PageItem):
  
  def __init__(self, matrix, font, fontsize, charspace, scaling, chars):
    assert chars
    self.matrix = matrix
    self.font = font
    (_,_,_,_,tx,ty) = self.matrix
    self.vertical = self.font.is_vertical()
    self.text = ''.join( char for (char,_) in chars )
    adv = sum( font.char_width(cid) for (_,cid) in chars )
    adv = (adv * fontsize + len(chars)*charspace) * scaling * .01
    size = (font.get_ascent() - font.get_descent()) * fontsize
    if not self.vertical:
      # horizontal text
      self.vertical = False
      (dx,dy) = apply_matrix_norm(self.matrix, (adv,size))
      (_,descent) = apply_matrix_norm(self.matrix, (0,font.get_descent() * fontsize))
      ty += descent
      self.adv = (dx, 0)
      bbox = (tx, ty, tx+dx, ty+dy)
    else:
      # vertical text
      (_,cid) = chars[0]
      (_,disp) = apply_matrix_norm(self.matrix, (0, (1000-font.char_disp(cid))*fontsize*.001))
      (dx,dy) = apply_matrix_norm(self.matrix, (size,adv))
      tx -= dx/2
      ty += disp
      self.adv = (0, dy)
      bbox = (tx, ty+dy, tx+dx, ty)
    self.fontsize = max(apply_matrix_norm(self.matrix, (size,size)))
    PageItem.__init__(self, bbox)
    return

  def __len__(self):
    return len(self.text)
  
  def __repr__(self):
    return ('<text matrix=%s font=%r fontsize=%.1f bbox=%s adv=%s text=%r>' %
            (matrix2str(self.matrix), self.font, self.fontsize, self.bbox(),
             point2str(self.adv), self.text))


##  bsearch
##
##  Finds objects whose coordinates overlap with [v0,v1].
##  It performs binary search so that the processing time
##  should be around O(log n).
##
def bsearch(objs, v0, v1):
  if v1 <= v0: return []
  i0 = 0
  i1 = len(objs)-1
  while i0 <= i1:
    i = (i0+i1)/2
    assert 0 <= i and i < len(objs)
    (v, obj) = objs[i]
    if v < v0:
      i0 = i+1
    elif v1 < v:
      i1 = i-1
    else:
      i0 = i
      while 0 < i0:
        (v,_) = objs[i0-1]
        if v < v0: break
        i0 -= 1
      i1 = i
      while i1 < len(objs)-1:
        (v,_) = objs[i1+1]
        if v1 < v: break
        i1 += 1
      return [ obj for (_,obj) in objs[i0:i1+1] ]
  return []


##  reorder_hv, reorder_vh
##
##  Reorders objects according to its writing direction.
##
def reorder_hv(objs, hdir):
  if 0 < hdir:
    hkey = (lambda obj: obj.x0)
  else:
    hkey = (lambda obj: -obj.x1)
  vkey = (lambda obj: -obj.y1)
  r = []
  line = []
  for obj1 in sorted(objs, key=vkey):
    if line and not line[-1].voverlap(obj1):
      line.sort(key=hkey)
      r.append(line)
      line = []
    line.append(obj1)
  line.sort(key=hkey)
  r.append(line)
  return r

def reorder_vh(objs, hdir):
  if 0 < hdir:
    hkey = (lambda obj: obj.x0)
  else:
    hkey = (lambda obj: -obj.x1)
  vkey = (lambda obj: -obj.y1)
  r = []
  line = []
  for obj1 in sorted(objs, key=hkey):
    if line and not line[-1].hoverlap(obj1):
      line.sort(key=vkey)
      r.append(line)
      line = []
    line.append(obj1)
  line.sort(key=vkey)
  r.append(line)
  return r


##  Plane
##
##  A data structure for objects placed on a plane.
##  Can efficiently find objects in a certain rectangular area.
##  It maintains two parallel lists of objects, each of
##  which is sorted by its x or y coordinate.
##
class Plane(object):

  def __init__(self, objs):
    self.xobjs = []
    self.yobjs = []
    for obj in objs:
      self.place(obj)
    self.fixate()
    return

  # place(obj): place an object in a certain area.
  def place(self, obj):
    self.xobjs.append((obj.x0, obj))
    self.xobjs.append((obj.x1, obj))
    self.yobjs.append((obj.y0, obj))
    self.yobjs.append((obj.y1, obj))
    return

  # fixate(): you must call this after adding all objects.
  def fixate(self):
    self.xobjs.sort()
    self.yobjs.sort()
    return

  # find(): finds objects that are in a certain area.
  def find(self, (x0,y0,x1,y1)):
    xobjs = set(bsearch(self.xobjs, x0, x1))
    yobjs = set(bsearch(self.yobjs, y0, y1))
    objs = xobjs.intersection(yobjs)
    return objs


##  TextBox
##
##  A set of text objects that are clustered in
##  a certain rectangular area.
##
class TextBox(PageItem):

  def __init__(self, objs):
    self.objs = set(objs)
    self.vertical = False
    self.length = None
    return

  def __repr__(self):
    return ('<textbox %s %s items=%d>' % (self.bbox(), self.vertical, len(self.objs)))

  def __len__(self):
    return self.length
  
  # merge(boxes): merges with other textboxes.
  def merge(self, box):
    self.objs.update(box.objs)
    return

  # finish(): determines its boundery and writing direction.
  def finish(self):
    assert self.objs
    (bx0, by0, bx1, by1) = (INF, INF, -INF, -INF)
    for obj in self.objs:
      bx0 = min(bx0, obj.x0)
      by0 = min(by0, obj.y0)
      bx1 = max(bx1, obj.x1)
      by1 = max(by1, obj.y1)
    PageItem.__init__(self, (bx0, by0, bx1, by1))
    self.length = sum( len(obj) for obj in self.objs )
    for obj in self.objs:
      self.vertical = obj.vertical
      break
    if 2 <= len(self.objs):
      objs = sorted(self.objs, key=lambda obj: -obj.x1-obj.y1)
      if len(objs[0]) == 1 and len(objs[1]) == 1:
        h = objs[0].voverlap(objs[1])
        v = objs[0].hoverlap(objs[1])
        self.vertical = (h < v)
    return

  def lines(self, ratio):
    if self.vertical:
      objs = sorted(self.objs, key=lambda obj: -obj.x1-obj.y1)
      for line in reorder_vh(objs, -1):
        s = ''
        y0 = -INF
        for obj in line:
          margin = abs(obj.fontsize * ratio)
          if obj.y1 < y0-margin:
            s += ' '
          s += obj.text
          y0 = obj.y0
        yield s
    else:
      objs = sorted(self.objs, key=lambda obj: obj.x0-obj.y1)
      for line in reorder_hv(objs, +1):
        s = ''
        x1 = INF
        for obj in line:
          margin = abs(obj.fontsize * ratio)
          if x1+margin < obj.x0:
            s += ' '
          s += obj.text
          x1 = obj.x1
        yield s
    return


##  ClusterSet
##
##  Maintains a set of TextBox objects.
##  It incrementally constructs TextBox objects
##  and group them when necessary. It gives
##  a sequence of TextBox objects that represent
##  the text stream of that page.
##
class ClusterSet(object):

  def __init__(self):
    self.clusters = {}
    return

  # add(objs): groups text objects if necessary.
  def add(self, objs):
    c = TextBox(objs)
    for obj in objs:
      if obj in self.clusters:
        c.merge(self.clusters[obj])
    for obj in c.objs:
      self.clusters[obj] = c
    return

  # finish(): returns all the TextBoxes in a page.
  def finish(self):
    r = set(self.clusters.itervalues())
    for textbox in r:
      textbox.finish()
    return r

# cluster_textobjs
def cluster_textobjs(objs, ratio):
  plane = Plane(objs)
  cset = ClusterSet()
  for obj in objs:
    margin = abs(obj.fontsize * ratio)
    neighbors = plane.find((obj.x0-margin, obj.y0-margin, obj.x1+margin, obj.y1+margin))
    cset.add(neighbors)
  clusters = cset.finish()
  vertical = ((sum( len(textbox) for textbox in clusters )/2) <
              sum( len(textbox) for textbox in clusters if textbox.vertical ))
  if vertical:
    lines = reorder_hv(clusters, -1)
  else:
    lines = reorder_vh(clusters, +1)
  r = []
  for line in lines:
    r.extend(line)
  return r
