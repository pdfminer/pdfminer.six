#!/usr/bin/env python
import sys
from pdfminer.utils import apply_matrix_norm, bsearch
INF = sys.maxint


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
    if line:
      v = line[-1].voverlap(obj) * 2
      if v < obj.height or v < line[-1].height:
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
    self.xobjs.sort()
    self.yobjs.sort()
    return

  # place(obj): place an object in a certain area.
  def place(self, obj):
    assert isinstance(obj, LayoutItem)
    self.xobjs.append((obj.x0, obj))
    self.xobjs.append((obj.x1, obj))
    self.yobjs.append((obj.y0, obj))
    self.yobjs.append((obj.y1, obj))
    return

  # find(): finds objects that are in a certain area.
  def find(self, (x0,y0,x1,y1)):
    (i0,_) = bsearch(self.xobjs, x0)
    (_,i1) = bsearch(self.xobjs, x1)
    xobjs = set( obj for (_,obj) in self.xobjs[i0:i1] )
    (i0,_) = bsearch(self.yobjs, y0)
    (_,i1) = bsearch(self.yobjs, y1)
    yobjs = set( obj for (_,obj) in self.yobjs[i0:i1] )
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
    group = self.klass(self.i, objs)
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
    return list(r)

def group_objs(objs, hratio, vratio, klass):
  plane = Plane(objs)
  cset = ClusterSet(klass)
  for obj in objs:
    margin = obj.get_margin()
    hmargin = hratio * margin
    vmargin = vratio * margin
    neighbors = plane.find((obj.x0-hmargin, obj.y0-vmargin, obj.x1+hmargin, obj.y1+vmargin))
    cset.add(neighbors)
  return cset.finish()


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
    return ('<item bbox=%s>' % (self.get_bbox()))
  
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
  
  def get_margin(self):
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
  def fixate(self, direction=None):
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
  

##  LTAnon
##
class LTAnon(object):

  def __init__(self, text):
    self.text = text
    return

  def get_weight(self):
    return 0


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

  def get_margin(self):
    return abs(self.fontsize)

  def get_weight(self):
    return len(self.text)
  
  def is_vertical(self):
    return self.vertical


##  LTFigure
##
class LTFigure(LayoutContainer):
  
  def __init__(self, id, bbox, matrix):
    LayoutContainer.__init__(self, id, bbox)
    self.matrix = matrix
    return

  def __repr__(self):
    return ('<figure id=%r bbox=%s matrix=%r>' % (self.id, self.get_bbox(), self.matrix))


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

  def fixate(self, direction='H'):
    LayoutContainer.fixate(self, direction=direction)
    if not direction:
      if any( obj.is_vertical() for obj in self.objs ):
        direction = 'V'
      if 2 <= len(self.objs):
        objs = sorted(self.objs, key=lambda obj: -obj.x1-obj.y1)
        if objs[0].get_weight() == 1 and objs[1].get_weight() == 1:
          h = objs[0].voverlap(objs[1])
          v = objs[0].hoverlap(objs[1])
          if h < v:
            direction = 'V'
    self.direction = direction
    if self.direction == 'V':
      self.lines = reorder_hv(self.objs, -1)
    else:
      self.lines = reorder_vh(self.objs, +1)
    self.objs = []
    for line in self.lines:
      self.objs.extend(line)
    return

  def get_direction(self):
    return self.direction

  def get_lines(self, word_margin):
    if self.get_direction() == 'V':
      for line in self.lines:
        y0 = -INF
        for obj in line:
          if not isinstance(obj, LTText): continue
          if word_margin:
            margin = word_margin * obj.get_margin()
            if obj.y1+margin < y0:
              yield LTAnon(' ')
          yield obj
          y0 = obj.y0
        yield LTAnon('\n')
    else:
      for line in self.lines:
        x1 = INF
        for obj in line:
          if not isinstance(obj, LTText): continue
          if word_margin:
            margin = word_margin * obj.get_margin()
            if x1 < obj.x0-margin:
              yield LTAnon(' ')
          yield obj
          x1 = obj.x1
        yield LTAnon('\n')
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

  def fixate(self, dirtection='H'):
    return

  def group_text(self, char_margin, line_margin):
    textobjs = [ obj for obj in self.objs if isinstance(obj, LTText) ]
    objs = [ obj for obj in self.objs if not isinstance(obj, LTText) ]
    if self.get_direction() == 'V':
      objs += group_objs(textobjs, line_margin, char_margin, LTTextBox)
      lines = reorder_hv(objs, -1)
    else:
      objs += group_objs(textobjs, char_margin, line_margin, LTTextBox)
      lines = reorder_vh(objs, +1)
    self.objs = []
    for line in lines:
      self.objs.extend(line)
    return
