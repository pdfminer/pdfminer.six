#!/usr/bin/env python
import sys
from sys import maxint as INF
from utils import apply_matrix_norm, apply_matrix_pt
from utils import bsearch, bbox2str, matrix2str
from pdffont import PDFUnicodeNotDefined



##  get_bounds
##
def get_bounds(pts):
    """Compute a maximal rectangle that covers all the points."""
    (x0, y0, x1, y1) = (INF, INF, -INF, -INF)
    for (x,y) in pts:
        x0 = min(x0, x)
        y0 = min(y0, y)
        x1 = max(x1, x)
        y1 = max(y1, y)
    return (x0,y0,x1,y1)

def uniq(objs):
    done = set()
    for obj in objs:
        if obj in done: continue
        done.add(obj)
        yield obj
    return


##  LAParams
##
class LAParams(object):

    def __init__(self,
                 direction=None,
                 line_overlap=0.5,
                 char_margin=3.0,
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


##  LayoutItem
##
class LayoutItem(object):

    def __init__(self, bbox):
        self.set_bbox(bbox)
        return

    def __repr__(self):
        return ('<item bbox=%s>' % bbox2str(self.bbox))

    def set_bbox(self, (x0,y0,x1,y1)):
        if x1 < x0: (x0,x1) = (x1,x0)
        if y1 < y0: (y0,y1) = (y1,y0)
        self.x0 = x0
        self.y0 = y0
        self.x1 = x1
        self.y1 = y1
        self.width = x1-x0
        self.height = y1-y0
        self.bbox = (x0, y0, x1, y1)
        return

    def is_hoverlap(self, obj):
        assert isinstance(obj, LayoutItem)
        return obj.x0 <= self.x1 and self.x0 <= obj.x1

    def hdistance(self, obj):
        assert isinstance(obj, LayoutItem)
        if self.is_hoverlap(obj):
            return 0
        else:
            return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))

    def hoverlap(self, obj):
        assert isinstance(obj, LayoutItem)
        if self.is_hoverlap(obj):
            return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))
        else:
            return 0

    def is_voverlap(self, obj):
        assert isinstance(obj, LayoutItem)
        return obj.y0 <= self.y1 and self.y0 <= obj.y1

    def vdistance(self, obj):
        assert isinstance(obj, LayoutItem)
        if self.is_voverlap(obj):
            return 0
        else:
            return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))

    def voverlap(self, obj):
        assert isinstance(obj, LayoutItem)
        if self.is_voverlap(obj):
            return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))
        else:
            return 0


##  LayoutContainer
##
class LayoutContainer(LayoutItem):

    def __init__(self, bbox, objs=None):
        LayoutItem.__init__(self, bbox)
        if objs:
            self.objs = objs[:]
        else:
            self.objs = []
        return

    def __repr__(self):
        return ('<container %s>' % bbox2str(self.bbox))

    def __iter__(self):
        return iter(self.objs)

    def __len__(self):
        return len(self.objs)

    def add(self, obj):
        self.objs.append(obj)
        return

    def merge(self, container):
        self.objs.extend(container.objs)
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
        return


##  LTPolygon
##
class LTPolygon(LayoutItem):

    def __init__(self, linewidth, pts):
        LayoutItem.__init__(self, get_bounds(pts))
        self.pts = pts
        self.linewidth = linewidth
        return

    def get_pts(self):
        return ','.join( '%.3f,%.3f' % p for p in self.pts )


##  LTLine
##
class LTLine(LTPolygon):

    def __init__(self, linewidth, p0, p1):
        LTPolygon.__init__(self, linewidth, [p0, p1])
        return


##  LTRect
##
class LTRect(LTPolygon):

    def __init__(self, linewidth, (x0,y0,x1,y1)):
        LTPolygon.__init__(self, linewidth, [(x0,y0), (x1,y0), (x1,y1), (x0,y1)])
        return


##  LTImage
##
class LTImage(LayoutItem):

    def __init__(self, name, type, srcsize, bbox, data):
        LayoutItem.__init__(self, bbox)
        self.name = name
        self.type = type
        self.srcsize = srcsize
        self.data = data
        return

    def __repr__(self):
        (w,h) = self.srcsize
        return '<image %s %s %dx%d>' % (self.name, self.type, w, h)


##  LTText
##
class LTText(object):

    def __init__(self, text):
        self.text = text
        return

    def __repr__(self):
        return '<text %r>' % self.text

    def is_upright(self):
        return True


##  LTAnon
##
class LTAnon(LTText):

    pass


##  LTChar
##
class LTChar(LayoutItem, LTText):

    debug = 1

    def __init__(self, matrix, font, fontsize, scaling, cid):
        self.matrix = matrix
        self.font = font
        self.fontsize = fontsize
        self.vertical = font.is_vertical()
        self.adv = font.char_width(cid) * fontsize * scaling
        try:
            text = font.to_unichr(cid)
        except PDFUnicodeNotDefined:
            text = '?'
        LTText.__init__(self, text)
        # compute the boundary rectangle.
        if self.vertical:
            # vertical
            size = font.get_size() * fontsize
            displacement = (1000 - font.char_disp(cid)) * fontsize * .001
            (_,displacement) = apply_matrix_norm(self.matrix, (0, displacement))
            (dx,dy) = apply_matrix_norm(self.matrix, (size, self.adv))
            (_,_,_,_,tx,ty) = self.matrix
            tx -= dx/2
            ty += displacement
            bbox = (tx, ty+dy, tx+dx, ty)
        else:
            # horizontal
            size = font.get_size() * fontsize
            descent = font.get_descent() * fontsize
            (_,descent) = apply_matrix_norm(self.matrix, (0, descent))
            (dx,dy) = apply_matrix_norm(self.matrix, (self.adv, size))
            (_,_,_,_,tx,ty) = self.matrix
            ty += descent
            bbox = (tx, ty, tx+dx, ty+dy)
        LayoutItem.__init__(self, bbox)
        return

    def __repr__(self):
        if self.debug:
            return ('<char matrix=%s font=%r fontsize=%.1f bbox=%s adv=%s text=%r>' %
                    (matrix2str(self.matrix), self.font, self.fontsize,
                     bbox2str(self.bbox), self.adv, self.text))
        else:
            return '<char %r>' % self.text

    def get_size(self):
        return max(self.width, self.height)

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
        bbox = get_bounds( apply_matrix_pt(matrix, (p,q))
                           for (p,q) in ((x,y), (x+w,y), (x,y+h), (x+w,y+h)) )
        self.id = id
        self.matrix = matrix
        LayoutContainer.__init__(self, bbox)
        return

    def __repr__(self):
        return ('<figure id=%r bbox=%s matrix=%s>' %
                (self.id, bbox2str(self.bbox), matrix2str(self.matrix)))


##  LTTextLine
##
class LTTextLine(LayoutContainer):

    def __init__(self, objs):
        LayoutContainer.__init__(self, (0,0,0,0), objs)
        return

    def __repr__(self):
        return ('<textline %s>' % bbox2str(self.bbox))

    def get_text(self):
        return ''.join( obj.text for obj in self.objs if isinstance(obj, LTText) )

    def find_neighbors(self, plane, ratio):
        raise NotImplementedError

class LTTextLineHorizontal(LTTextLine):

    def __init__(self, objs, word_margin):
        LTTextLine.__init__(self, objs)
        LayoutContainer.fixate(self)
        objs = []
        x1 = INF
        for obj in sorted(self.objs, key=lambda obj: obj.x0):
            if isinstance(obj, LTChar) and word_margin:
                margin = word_margin * obj.width
                if x1 < obj.x0-margin:
                    objs.append(LTAnon(' '))
            objs.append(obj)
            x1 = obj.x1
        self.objs = objs + [LTAnon('\n')]
        return

    def find_neighbors(self, plane, ratio):
        h = ratio*self.height
        return plane.find((self.x0, self.y0-h, self.x1, self.y1+h))
    
class LTTextLineVertical(LTTextLine):

    def __init__(self, objs, word_margin):
        LTTextLine.__init__(self, objs)
        LayoutContainer.fixate(self)
        objs = []
        y0 = -INF
        for obj in sorted(self.objs, key=lambda obj: -obj.y1):
            if isinstance(obj, LTChar) and word_margin:
                margin = word_margin * obj.height
                if obj.y1+margin < y0:
                    objs.append(LTAnon(' '))
            objs.append(obj)
            y0 = obj.y0
        self.objs = objs + [LTAnon('\n')]
        return

    def find_neighbors(self, plane, ratio):
        w = ratio*self.width
        return plane.find((self.x0-w, self.y0, self.x1+w, self.y1))
    

##  LTTextBox
##
##  A set of text objects that are grouped within
##  a certain rectangular area.
##
class LTTextBox(LayoutContainer):

    def __init__(self, objs):
        LayoutContainer.__init__(self, (0,0,0,0), objs)
        return

    def __repr__(self):
        return ('<textbox(%d) %s %r...>' % (len(self.objs), bbox2str(self.bbox), self.get_text()[:20]))

    def get_text(self):
        return ''.join( obj.get_text() for obj in self.objs if isinstance(obj, LTTextLine) )

class LTTextBoxHorizontal(LTTextBox):
    
    def fixate(self):
        LTTextBox.fixate(self)
        self.objs = sorted(self.objs, key=lambda obj: -obj.y1)
        return

class LTTextBoxVertical(LTTextBox):

    def fixate(self):
        LTTextBox.fixate(self)
        self.objs = sorted(self.objs, key=lambda obj: -obj.x1)
        return


##  LTTextFlow
##
class LTTextFlow(LayoutContainer):

    def __init__(self, objs):
        assert objs
        LayoutContainer.__init__(self, (0,0,0,0), objs)
        LayoutContainer.fixate(self)
        return

class LTTextFlowHorizontal(LTTextFlow):
    
    def __init__(self, objs):
        LTTextFlow.__init__(self, objs)
        # reorder the objects from top-left to bottom-right.
        self.objs = sorted(self.objs, key=lambda obj: obj.x0-obj.y1)
        return

class LTTextFlowVertical(LTTextFlow):
    
    def __init__(self, objs):
        LTTextFlow.__init__(self, objs)
        # reorder the objects from top-right to bottom-left.
        self.objs = sorted(self.objs, key=lambda obj: -obj.x1-obj.y1)
        return


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
        i0 = bsearch(self.xobjs, x0)[0]
        i1 = bsearch(self.xobjs, x1)[1]
        xobjs = set( obj for (_,obj) in self.xobjs[i0:i1] )
        i0 = bsearch(self.yobjs, y0)[0]
        i1 = bsearch(self.yobjs, y1)[1]
        yobjs = set( obj for (_,obj) in self.yobjs[i0:i1] )
        xobjs.intersection_update(yobjs)
        return list(xobjs)


##  ClusterBuilder
##
class ClusterBuilder(object):

    def __init__(self, groupfunc):
        self.clusters = {}
        self.groupfunc = groupfunc
        return

    # group(objs): groups given objects into one cluster.
    def group(self, objs):
        r = objs[:]
        for obj1 in objs:
            if obj1 in self.clusters:
                r.extend(self.clusters.pop(obj1))
        cluster = self.groupfunc(list(uniq(r)))
        for obj in r:
            self.clusters[obj] = cluster
        return

    # finish(): returns all the clusters.
    def finish(self):
        clusters = set(self.clusters.itervalues())
        for cluster in clusters:
            cluster.fixate()
        return list(clusters)

def build_boxes(groupfunc, objs, *args):
    plane = Plane(objs)
    builder = ClusterBuilder(groupfunc)
    for obj in objs:
        neighbors = obj.find_neighbors(plane, *args)
        assert obj in neighbors, obj
        builder.group(neighbors)
    return builder.finish()

def group_hier(groupfunc, objs, distfunc):
    assert objs
    while 2 <= len(objs):
        mindist = INF
        minpair = None
        objs.sort(key=lambda obj: obj.width*obj.height)
        for (i,obj0) in enumerate(objs):
            for obj1 in objs[i+1:]:
                d = distfunc(obj0, obj1)
                if d < mindist:
                    mindist = d
                    minpair = (obj0, obj1)
        assert minpair
        (obj0, obj1) = minpair
        objs.remove(obj0)
        objs.remove(obj1)
        objs.append(groupfunc([obj0, obj1]))
    assert len(objs) == 1
    return objs.pop()


##  LTPage
##
class LTPage(LayoutContainer):

    def __init__(self, id, bbox, rotate=0):
        LayoutContainer.__init__(self, bbox)
        self.id = id
        self.rotate = rotate
        return

    def __repr__(self):
        return ('<page id=%r bbox=%s rotate=%r>' % (self.id, bbox2str(self.bbox), self.rotate))

    def analyze_layout(self, laparams):
        textobjs = []
        otherobjs = []
        for obj in self.objs:
            if isinstance(obj, LTText) and obj.is_upright():
                textobjs.append(obj)
            else:
                otherobjs.append(obj)
        if laparams.direction == 'V':
            textobjs = self.analyze_layout_vertical(textobjs, laparams)
        else:
            textobjs = self.analyze_layout_horizontal(textobjs, laparams)
        self.objs = [textobjs] + otherobjs
        return

    def analyze_layout_horizontal(self, objs, laparams):
        
        def halign(obj1, obj2):
            # +------+ - - -
            # | obj1 | - - +------+   -
            # |      |     | obj2 |   | (line_overlap)
            # +------+ - - |      |   -
            #        - - - +------+
            #
            #        |<--->|
            #      (char_margin)
            return ((min(obj1.height, obj2.height) * laparams.line_overlap < obj1.voverlap(obj2)) and
                    (obj1.hdistance(obj2) < min(obj1.width, obj2.width) * laparams.char_margin))
        
        lines = []
        line = []
        prev = None
        for cur in objs:
            if prev is not None and not halign(prev, cur):
                if line:
                    lines.append(LTTextLineHorizontal(line, laparams.word_margin))
                    line = []
            line.append(cur)
            prev = cur
        if line:
            lines.append(LTTextLineHorizontal(line, laparams.word_margin))
        boxes = build_boxes(LTTextBoxHorizontal, lines, laparams.line_margin)

        def dist(obj1, obj2):
            return ((max(obj1.x1,obj2.x1) - min(obj1.x0,obj2.x0)) *
                    (max(obj1.y1,obj2.y1) - min(obj1.y0,obj2.y0)) -
                    obj1.width*obj1.height - obj2.width*obj2.height)
        
        return group_hier(LTTextFlowHorizontal, boxes, dist)

    def analyze_layout_vertical(self, objs, laparams):

        def valign(obj1, obj2):
            # +------+
            # | obj1 |
            # |      |
            # +------+ - - -
            #   |    |     | (char_margin)
            #   +------+ - -
            #   | obj2 |
            #   |      |
            #   +------+
            #
            #   |<--->|
            # (line_overlap)
            return ((min(obj1.width, obj2.width) * laparams.line_overlap < obj1.hoverlap(obj2)) and
                    (obj1.vdistance(obj2) < min(obj1.height, obj2.height) * laparams.char_margin))
        
        lines = []
        line = []
        prev = None
        for cur in objs:
            if prev is not None and not valign(prev, cur):
                if line:
                    lines.append(LTTextLineVertical(line, laparams.word_margin))
                    line = []
            line.append(cur)
            prev = cur
        if line:
            lines.append(LTTextLineVertical(line, laparams.word_margin))
        boxes = build_boxes(LTTextBoxVertical, lines, laparams.line_margin)

        def dist(obj1, obj2):
            return ((max(obj1.x1,obj2.x1) - min(obj1.x0,obj2.x0)) *
                    (max(obj1.y1,obj2.y1) - min(obj1.y0,obj2.y0)) -
                    obj1.width*obj1.height - obj2.width*obj2.height)

        return group_hier(LTTextFlowVertical, boxes, dist)
