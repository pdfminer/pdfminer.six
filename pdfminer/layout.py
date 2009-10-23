#!/usr/bin/env python
import sys
from pdfminer.utils import apply_matrix_norm, apply_matrix_pt, bsearch
INF = sys.maxint


##  LAParams
##
class LAParams(object):
  
  def __init__(self,
               direction=None,
               line_overlap=0.5,
               char_margin=1.0,
               line_margin=0.5,
               word_margin=0.1):
    self.direction = direction
    self.line_overlap = line_overlap
    self.char_margin = char_margin
    self.line_margin = line_margin
    self.word_margin = word_margin
    return

  def __repr__(self):
    return ('<LAParams: direction=%r, char_margin=%.1f, line_margin=%.1f, word_margin=%.1f>' %
            (self.direction, self.char_margin, self.line_margin, self.word_margin))


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

  @classmethod
  def build(klass, objs, hratio, vratio, objtype, func=None):
    plane = Plane(objs)
    cset = ClusterSet(objtype)
    for obj in objs:
      margin = obj.get_margin()
      hmargin = hratio * margin
      vmargin = vratio * margin
      neighbors = plane.find((obj.x0-hmargin, obj.y0-vmargin, obj.x1+hmargin, obj.y1+vmargin))
      assert obj in neighbors, obj
      if func:
        neighbors = [ x for x in neighbors if x is obj or func(obj, x) ]
      cset.add(neighbors)
    return cset.finish()


##  LayoutItem
##
class LayoutItem(object):

  def __init__(self, bbox):
    self.set_bbox(bbox)
    return

  def set_bbox(self, (x0,y0,x1,y1)):
    if x1 < x0: (x0,x1) = (x1,x0)
    if y1 < y0: (y0,y1) = (y1,y0)
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

  def __len__(self):
    return len(self.objs)
  
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

  def get_weight(self):
    return self.weight
  
  def get_direction(self):
    return None


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
  

##  LTText
##
class LTText(object):

  def __init__(self, text):
    self.text = text
    return

  def __repr__(self):
    return '<text %r>' % self.text

  def get_weight(self):
    return len(self.text)

  def is_upright(self):
    return True


##  LTAnon
##
class LTAnon(LTText):

  def get_weight(self):
    return 0


##  LTTextItem
##
class LTTextItem(LayoutItem, LTText):

  debug = 1
  
  def __init__(self, matrix, font, fontsize, charspace, scaling, chars):
    assert chars
    self.matrix = matrix
    self.font = font
    self.vertical = font.is_vertical()
    self.text = ''.join( char for (char,_) in chars )
    adv = sum( font.char_width(cid) for (_,cid) in chars )
    adv = (adv * fontsize + (len(chars)-1)*charspace) * scaling
    #size = (font.get_ascent() - font.get_descent()) * fontsize
    size = font.get_size() * fontsize
    (_,_,_,_,tx,ty) = self.matrix
    if not self.vertical:
      # horizontal text
      self.adv = (adv, 0)
      (dx,dy) = apply_matrix_norm(self.matrix, (adv,size))
      (_,descent) = apply_matrix_norm(self.matrix, (0,font.get_descent() * fontsize))
      ty += descent
      bbox = (tx, ty, tx+dx, ty+dy)
    else:
      # vertical text
      self.adv = (0, adv)
      (_,cid) = chars[0]
      (_,disp) = apply_matrix_norm(self.matrix, (0, (1000-font.char_disp(cid))*fontsize*.001))
      (dx,dy) = apply_matrix_norm(self.matrix, (size,adv))
      tx -= dx/2
      ty += disp
      bbox = (tx, ty+dy, tx+dx, ty)
    self.fontsize = max(apply_matrix_norm(self.matrix, (size,size)))
    LayoutItem.__init__(self, bbox)
    return

  def __repr__(self):
    if self.debug:
      return ('<text matrix=%s font=%r fontsize=%.1f bbox=%s adv=%s text=%r>' %
              ('[%.1f, %.1f, %.1f, %.1f, (%.1f, %.1f)]' % self.matrix,
               self.font, self.fontsize, self.get_bbox(),
               '(%.1f, %.1f)' % self.adv,
               self.text))
    else:
      return '<text %r>' % self.text

  def get_margin(self):
    return abs(self.fontsize)

  def is_vertical(self):
    return self.vertical

  def is_upright(self):
    (a,b,c,d,e,f) = self.matrix
    return 0 < a*d and b*c <= 0


##  LTFigure
##
class LTFigure(LayoutContainer):
  
  def __init__(self, id, bbox, matrix):
    (x,y,w,h) = bbox
    x0 = y0 = INF
    x1 = y1 = -INF
    for (p,q) in ((x,y),(x+w,y),(x,y+h),(x+w,y+h)):
      (p,q) = apply_matrix_pt(matrix, (p,q))
      x0 = min(x0, p)
      x1 = max(x1, p)
      y0 = min(y0, q)
      y1 = max(y1, q)
    bbox = (x0,y0,x1,y1)
    self.matrix = matrix
    LayoutContainer.__init__(self, id, bbox)
    return

  def __repr__(self):
    return ('<figure id=%r bbox=%s matrix=%r>' % (self.id, self.get_bbox(), self.matrix))


##  LTTextLine
##
class LTTextLine(LayoutContainer):

  def __init__(self, id, objs, direction, word_margin):
    LayoutContainer.__init__(self, id, (0,0,0,0), objs)
    self.direction = direction
    self.word_margin = word_margin
    return

  def __repr__(self):
    return ('<line %s(%s)>' % (self.get_bbox(), self.direction))

  def get_margin(self):
    return min(self.width, self.height)

  def get_direction(self):
    return self.direction

  def get_text(self):
    return ''.join( obj.text for obj in self.objs if isinstance(obj, LTText) )

  def fixate(self):
    LayoutContainer.fixate(self)
    objs = []
    if self.direction == 'V':
      y0 = -INF
      for obj in sorted(self.objs, key=lambda obj: -obj.y1):
        if isinstance(obj, LTTextItem) and self.word_margin:
          margin = self.word_margin * obj.get_margin()
          if obj.y1+margin < y0:
            objs.append(LTAnon(' '))
        objs.append(obj)
        y0 = obj.y0
    else:
      x1 = INF
      for obj in sorted(self.objs, key=lambda obj: obj.x0):
        if isinstance(obj, LTTextItem) and self.word_margin:
          margin = self.word_margin * obj.get_margin()
          if x1 < obj.x0-margin:
            objs.append(LTAnon(' '))
        objs.append(obj)
        x1 = obj.x1
    objs.append(LTAnon('\n'))
    self.objs = objs
    return


##  LTTextBox
##
##  A set of text objects that are grouped within
##  a certain rectangular area.
##
class LTTextBox(LayoutContainer):

  def __init__(self, id, objs, direction):
    LayoutContainer.__init__(self, id, (0,0,0,0), objs)
    self.direction = direction
    return

  def __repr__(self):
    return ('<textbox %s(%s) %r...>' % (self.get_bbox(), self.direction, self.get_text()[:20]))

  def get_text(self):
    return ''.join( obj.get_text() for obj in self.objs if isinstance(obj, LTTextLine) )
  
  def fixate(self):
    LayoutContainer.fixate(self)
    if self.direction == 'V':
      self.objs = sorted(self.objs, key=lambda obj: -obj.x1)
    else:
      self.objs = sorted(self.objs, key=lambda obj: -obj.y1)
    return

  def get_direction(self):
    return self.direction


def tsort(objs, f):
  gi = dict( (obj,[]) for obj in objs )
  go = dict( (obj,[]) for obj in objs )
  for obj1 in objs:
    for obj2 in objs:
      if obj1 is obj2: continue
      if f(obj1, obj2): # obj1 -> obj2
        go[obj1].append(obj2)
        gi[obj2].append(obj1)
  r = objs[:]
  s = []
  while r:
    for obj in r:
      if not go[obj] or gi[obj]: continue
      for c in go[obj]:
        gi[c].remove(obj)
      del gi[obj]
      del go[obj]
      r.remove(obj)
      s.append(obj)
      break
    else:
      obj = r.pop()
      del gi[obj]
      del go[obj]
      s.append(obj)
  return s


##  LTPage
##
class LTPage(LayoutContainer):
  
  def __init__(self, id, bbox, rotate=0):
    LayoutContainer.__init__(self, id, bbox)
    self.rotate = rotate
    return
  
  def __repr__(self):
    return ('<page id=%r bbox=%s rotate=%r>' % (self.id, self.get_bbox(), self.rotate))

  def analyze_layout(self, laparams):
    textobjs = []
    otherobjs = []
    for obj in self.objs:
      if isinstance(obj, LTText) and obj.is_upright():
        textobjs.append(obj)
      else:
        otherobjs.append(obj)
    if laparams.direction == 'V':
      def vline(obj1, obj2):
        return obj1.width * laparams.line_overlap < obj1.hoverlap(obj2)
      def vorder(obj1, obj2):
        if obj1.voverlap(obj2):
          return obj2.x1 < obj1.x0
        elif obj1.hoverlap(obj2):
          return obj2.y1 < obj1.y0
        else:
          return obj2.x1 < obj1.x0 and obj2.y1 < obj1.y0
      lines = ClusterSet.build(textobjs, 0, laparams.char_margin,
                               (lambda id,objs: LTTextLine(id, objs, 'V', laparams.word_margin)),
                               vline)
      boxes = ClusterSet.build(lines, laparams.line_margin, 0,
                               (lambda id,objs: LTTextBox(id, objs, 'V')))
      boxes = tsort(boxes, vorder)
    else:
      def hline(obj1, obj2):
        return obj1.height * laparams.line_overlap < obj1.voverlap(obj2)
      def horder(obj1, obj2):
        if obj1.hoverlap(obj2):
          return obj2.y1 < obj1.y0
        elif obj1.voverlap(obj2):
          return obj1.x1 < obj2.x0
        else:
          return obj1.x1 < obj2.x0 and obj2.y1 < obj1.y0
      lines = ClusterSet.build(textobjs, laparams.char_margin, 0,
                               (lambda id,objs: LTTextLine(id, objs, 'H', laparams.word_margin)),
                               hline)
      boxes = ClusterSet.build(lines, 0, laparams.line_margin,
                               (lambda id,objs: LTTextBox(id, objs, 'H')))
      boxes = tsort(boxes, horder)
    self.objs = otherobjs + boxes
    return
