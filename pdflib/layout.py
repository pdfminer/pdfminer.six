#!/usr/bin/env python
import sys
from utils import apply_matrix_norm
INF = sys.maxint


##  pick
##
def pick(seq, func, maxobj=None):
  maxscore = None
  for obj in seq:
    score = func(obj)
    if maxscore == None or maxscore < score:
      (maxscore,maxobj) = (score,obj)
  return maxobj


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
##  chop_hv, chop_vh
##
##  Reorders objects according to its writing direction.
##
def reorder_vh(objs, hdir):
  if 0 < hdir:
    hkey = (lambda obj: obj.x0)
    vkey = (lambda obj: -obj.y1)
  else:
    hkey = (lambda obj: -obj.x1)
    vkey = (lambda obj: -obj.y1)
  r = []
  line = []
  for obj in sorted(objs, key=vkey):
    if line and not line[-1].voverlap(obj):
      line.sort(key=hkey)
      r.append(line)
      line = []
    line.append(obj)
  line.sort(key=hkey)
  r.append(line)
  return r

def reorder_hv(objs, hdir):
  if 0 < hdir:
    hkey = (lambda obj: obj.x0)
    vkey = (lambda obj: -obj.y1)
  else:
    hkey = (lambda obj: -obj.x1)
    vkey = (lambda obj: -obj.y1)
  r = []
  line = []
  for obj in sorted(objs, key=hkey):
    if line and not line[-1].hoverlap(obj):
      line.sort(key=vkey)
      r.append(line)
      line = []
    line.append(obj)
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
    assert isinstance(obj, LayoutItem)
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


##  ClusterSet
##
##  Maintains a set of LTTextBox objects.
##  It incrementally constructs LTTextBox objects
##  and group them when necessary. It gives
##  a sequence of LTTextBox objects that represent
##  the text stream of that page.
##
class ClusterSet(object):

  def __init__(self, klass):
    self.clusters = {}
    self.klass = klass
    self.i = 0
    return

  # add(objs): groups text objects if necessary.
  def add(self, objs):
    group = self.klass(objs, self.i)
    self.i += 1
    for obj in objs:
      if obj in self.clusters:
        group.merge(self.clusters[obj])
    for obj in group:
      self.clusters[obj] = group
    return

  # finish(): returns all the LTTextBoxes in a page.
  def finish(self):
    r = set(self.clusters.itervalues())
    for group in r:
      group.fixate()
    return r


##  LayoutItem
##
class LayoutItem(object):

  def __init__(self, bbox):
    #assert x0 <= x1 and y0 <= y1
    self.set_bbox(bbox)
    return

  def set_bbox(self, (x0,y0,x1,y1)):
    self.x0 = x0
    self.y0 = y0
    self.x1 = x1
    self.y1 = y1
    self.width = x1-x0
    self.height = y1-y0
    return

  def __repr__(self):
    return ('<pageitem bbox=%s>' % (self.get_bbox()))
  
  def hoverlap(self, obj):
    assert isinstance(obj, LayoutItem)
    if self.x1 <= obj.x0 or obj.x1 <= self.x0:
      return 0
    else:
      return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))

  def voverlap(self, obj):
    assert isinstance(obj, LayoutItem)
    if self.y1 <= obj.y0 or obj.y1 <= self.y0:
      return 0
    else:
      return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))

  def get_bbox(self):
    return '%.3f,%.3f,%.3f,%.3f' % (self.x0, self.y0, self.x1, self.y1)
  
  def get_margin(self, ratio):
    return 0

  def get_weight(self):
    return 0
  
  def get_direction(self):
    return None

  
##  LayoutContainer
##
class LayoutContainer(LayoutItem):
  
  def __init__(self, id, bbox, objs=None):
    LayoutItem.__init__(self, bbox)
    self.id = id
    if objs:
      self.objs = set(objs)
    else:
      self.objs = set()
    self.weight = None
    return

  def __repr__(self):
    return ('<group %s>' % (self.get_bbox()))

  def __iter__(self):
    return iter(self.objs)
  
  def add(self, obj):
    self.objs.add(obj)
    return

  def merge(self, group):
    self.objs.update(iter(group))
    return

  # fixate(): determines its boundery and writing direction.
  def fixate(self):
    if not self.width and self.objs:
      (bx0, by0, bx1, by1) = (INF, INF, -INF, -INF)
      for obj in self.objs:
        bx0 = min(bx0, obj.x0)
        by0 = min(by0, obj.y0)
        bx1 = max(bx1, obj.x1)
        by1 = max(by1, obj.y1)
      self.set_bbox((bx0, by0, bx1, by1))
    self.weight = sum( obj.get_weight() for obj in self.objs )
    return

  def group_objs(self, ratio, klass):
    plane = Plane(self.objs)
    cset = ClusterSet(klass)
    for obj in self.objs:
      margin = abs(obj.get_margin(ratio))
      neighbors = plane.find((obj.x0-margin, obj.y0-margin, obj.x1+margin, obj.y1+margin))
      cset.add(neighbors)
    self.objs = cset.finish()
    return
  
  def get_weight(self):
    return self.weight
  
  def get_direction(self):
    if not self.objs: return None
    d = {}
    for obj in self.objs:
      k = obj.get_direction()
      if k not in d: d[k] = 0
      d[k] += 1
    (direction,_) = sorted(d.iteritems(), key=lambda (k,v):v)[0]
    return direction


##  LTLine
##
class LTLine(LayoutItem):

  def __init__(self, linewidth, direction, bbox):
    LayoutItem.__init__(self, bbox)
    self.linewidth = linewidth
    self.direction = direction
    return


##  LTRect
##
class LTRect(LayoutItem):

  def __init__(self, linewidth, bbox):
    LayoutItem.__init__(self, bbox)
    self.linewidth = linewidth
    return
  

##  LTFigure
##
class LTFigure(LayoutContainer):
  
  def __repr__(self):
    return ('<figure id=%r bbox=%s>' % (self.id, self.get_bbox()))


##  LTText
##
class LTText(LayoutItem):
  
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
    LayoutItem.__init__(self, bbox)
    return

  def __repr__(self):
    return ('<text matrix=%s font=%r fontsize=%.1f bbox=%s adv=%s text=%r>' %
            ('[%.1f, %.1f, %.1f, %.1f, (%.1f, %.1f)]' % self.matrix,
             self.font, self.fontsize, self.get_bbox(),
             '(%.1f, %.1f)' % self.adv,
             self.text))

  def get_margin(self, ratio):
    return self.fontsize * ratio

  def get_weight(self):
    return len(self.text)
  
  def is_vertical(self):
    return self.vertical


##  LTTextBox
##
##  A set of text objects that are grouped within
##  a certain rectangular area.
##
class LTTextBox(LayoutContainer):

  def __init__(self, id, objs):
    LayoutContainer.__init__(self, id, (0,0,0,0), objs)
    self.direction = None
    return

  def __repr__(self):
    return ('<textbox %s(%s)>' % (self.get_bbox(), self.direction))

  def fixate(self):
    LayoutContainer.fixate(self)
    self.direction = 'H'
    for obj in self.objs:
      if obj.is_vertical():
        self.direction = 'V'
      break
    if 2 <= len(self.objs):
      objs = sorted(self.objs, key=lambda obj: -obj.x1-obj.y1)
      if objs[0].get_weight() == 1 and objs[1].get_weight() == 1:
        h = objs[0].voverlap(objs[1])
        v = objs[0].hoverlap(objs[1])
        if h < v:
          self.direction = 'V'
    if self.direction == 'H':
      self.lines = reorder_vh(self.objs, +1)
    else:
      self.lines = reorder_hv(self.objs, -1)
    self.objs = []
    for line in self.lines:
      self.objs.extend(line)
    return

  def get_direction(self):
    return self.direction

  def get_lines(self, ratio):
    if self.get_direction() == 'H':
      for line in self.lines:
        s = ''
        x1 = INF
        for obj in line:
          if not isinstance(obj, LTText): continue
          margin = obj.get_margin(ratio)
          if x1 < obj.x0-margin:
            s += ' '
          s += obj.text
          x1 = obj.x1
        yield s
    else:
      for line in self.lines:
        s = ''
        y0 = -INF
        for obj in line:
          if not isinstance(obj, LTText): continue
          margin = obj.get_margin(ratio)
          if obj.y1+margin < y0:
            s += ' '
          s += obj.text
          y0 = obj.y0
        yield s
    return


##  LTPage
##
class LTPage(LayoutContainer):
  
  def __init__(self, id, bbox, rotate=0):
    LayoutContainer.__init__(self, id, bbox)
    self.rotate = rotate
    return
  
  def __repr__(self):
    return ('<page id=%r bbox=%s rotate=%r>' % (self.id, self.get_bbox(), self.rotate))

  def fixate(self):
    return

  def group_text(self, ratio):
    self.group_objs(ratio, LTTextBox)
    if self.get_direction() == 'H':
      lines = reorder_vh(self.objs, +1)
    else:
      lines = reorder_hv(self.objs, -1)
    self.objs = []
    for line in lines:
      self.objs.extend(line)
    return
