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

def csort(objs, key):
    idxs = dict( (obj,i) for (i,obj) in enumerate(objs) )
    return sorted(objs, key=lambda obj:(key(obj), idxs[obj]))

def is_uniq(objs):
    for (i,obj1) in enumerate(objs):
        for obj2 in objs[i+1:]:
            if obj1 == obj2: return False
    return True


##  LAParams
##
class LAParams(object):

    def __init__(self,
                 writing_mode='lr-tb',
                 line_overlap=0.5,
                 char_margin=3.0,
                 line_margin=0.5,
                 word_margin=0.1,
                 all_texts=False):
        self.writing_mode = writing_mode
        self.line_overlap = line_overlap
        self.char_margin = char_margin
        self.line_margin = line_margin
        self.word_margin = word_margin
        self.all_texts = all_texts
        return

    def __repr__(self):
        return ('<LAParams: writing_mode=%r, char_margin=%.1f, line_margin=%.1f, word_margin=%.1f all_texts=%r>' %
                (self.writing_mode, self.char_margin, self.line_margin, self.word_margin, self.all_texts))


##  LTItem
##
class LTItem(object):

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
        assert isinstance(obj, LTItem)
        return obj.x0 <= self.x1 and self.x0 <= obj.x1

    def hdistance(self, obj):
        assert isinstance(obj, LTItem)
        if self.is_hoverlap(obj):
            return 0
        else:
            return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))

    def hoverlap(self, obj):
        assert isinstance(obj, LTItem)
        if self.is_hoverlap(obj):
            return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))
        else:
            return 0

    def is_voverlap(self, obj):
        assert isinstance(obj, LTItem)
        return obj.y0 <= self.y1 and self.y0 <= obj.y1

    def vdistance(self, obj):
        assert isinstance(obj, LTItem)
        if self.is_voverlap(obj):
            return 0
        else:
            return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))

    def voverlap(self, obj):
        assert isinstance(obj, LTItem)
        if self.is_voverlap(obj):
            return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))
        else:
            return 0


##  LTPolygon
##
class LTPolygon(LTItem):

    def __init__(self, linewidth, pts):
        LTItem.__init__(self, get_bounds(pts))
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
class LTImage(LTItem):

    def __init__(self, name, stream, bbox):
        LTItem.__init__(self, bbox)
        self.name = name
        self.stream = stream
        self.srcsize = (stream.get_any(('W', 'Width')),
                        stream.get_any(('H', 'Height')))
        self.imagemask = stream.get_any(('IM', 'ImageMask'))
        self.bits = stream.get_any(('BPC', 'BitsPerComponent'), 1)
        self.colorspace = stream.get_any(('CS', 'ColorSpace'))
        if not isinstance(self.colorspace, list):
            self.colorspace = [self.colorspace]
        return

    def __repr__(self):
        (w,h) = self.srcsize
        return '<image %s %dx%d>' % (self.name, w, h)


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
class LTChar(LTItem, LTText):

    debug = 0

    def __init__(self, matrix, font, fontsize, scaling, rise, cid):
        self.matrix = matrix
        self.font = font
        self.fontsize = fontsize
        self.vertical = font.is_vertical()
        self.adv = font.char_width(cid) * fontsize * scaling
        try:
            text = font.to_unichr(cid)
        except PDFUnicodeNotDefined:
            text = '?'
        (a,b,c,d,e,f) = self.matrix
        self.upright = (0 < a*d*scaling and b*c <= 0)
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
            ty += displacement + rise
            bbox = (tx, ty+dy, tx+dx, ty)
        else:
            # horizontal
            size = font.get_size() * fontsize
            descent = font.get_descent() * fontsize
            (_,descent) = apply_matrix_norm(self.matrix, (0, descent))
            (dx,dy) = apply_matrix_norm(self.matrix, (self.adv, size))
            (_,_,_,_,tx,ty) = self.matrix
            ty += descent + rise
            bbox = (tx, ty, tx+dx, ty+dy)
        LTItem.__init__(self, bbox)
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
        return self.upright

    
##  LTContainer
##
class LTContainer(LTItem):

    def __init__(self, bbox, objs=None):
        LTItem.__init__(self, bbox)
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

    # fixate(): determines its boundery.
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


##  LTTextLine
##
class LTTextLine(LTContainer):

    def __init__(self, objs):
        LTContainer.__init__(self, (0,0,0,0), objs)
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
        LTContainer.fixate(self)
        objs = []
        x1 = INF
        for obj in csort(self.objs, key=lambda obj: obj.x0):
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
        LTContainer.fixate(self)
        objs = []
        y0 = -INF
        for obj in csort(self.objs, key=lambda obj: -obj.y1):
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
class LTTextBox(LTContainer):

    def __init__(self, objs):
        LTContainer.__init__(self, (0,0,0,0), objs)
        self.index = None
        return

    def __repr__(self):
        return ('<textbox(%s) %s %r...>' % (self.index, bbox2str(self.bbox), self.get_text()[:20]))

    def get_text(self):
        return ''.join( obj.get_text() for obj in self.objs if isinstance(obj, LTTextLine) )

class LTTextBoxHorizontal(LTTextBox):
    
    def fixate(self):
        LTTextBox.fixate(self)
        self.objs = csort(self.objs, key=lambda obj: -obj.y1)
        return

class LTTextBoxVertical(LTTextBox):

    def fixate(self):
        LTTextBox.fixate(self)
        self.objs = csort(self.objs, key=lambda obj: -obj.x1)
        return


##  LTTextGroup
##
class LTTextGroup(LTContainer):

    def __init__(self, objs):
        assert objs
        LTContainer.__init__(self, (0,0,0,0), objs)
        LTContainer.fixate(self)
        return

class LTTextGroupLRTB(LTTextGroup):
    
    def __init__(self, objs):
        LTTextGroup.__init__(self, objs)
        # reorder the objects from top-left to bottom-right.
        self.objs = csort(self.objs, key=lambda obj: obj.x0+obj.x1-(obj.y0+obj.y1))
        return

class LTTextGroupTBRL(LTTextGroup):
    
    def __init__(self, objs):
        LTTextGroup.__init__(self, objs)
        # reorder the objects from top-right to bottom-left.
        self.objs = csort(self.objs, key=lambda obj: -(obj.x0+obj.x1)-(obj.y0+obj.y1))
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
        self.idxs = dict( (obj,i) for (i,obj) in enumerate(objs) )
        for obj in objs:
            self.place(obj)
        self.xobjs.sort()
        self.yobjs.sort()
        return

    # place(obj): place an object in a certain area.
    def place(self, obj):
        assert isinstance(obj, LTItem)
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
        return sorted(xobjs, key=lambda obj: self.idxs[obj])


##  guess_wmode
##
def guess_wmode(objs):
    """Guess the writing mode by looking at the order of text objects."""
    xy = tb = lr = 0
    obj0 = None
    for obj1 in objs:
        if obj0 is not None:
            dx = obj1.x0+obj1.x1-(obj0.x0+obj0.x1)
            dy = obj1.y0+obj1.y1-(obj0.y0+obj0.y1)
            if abs(dy) < abs(dx):
                xy += 1
            else:
                xy -= 1
            if 0 < dx:
                lr += 1
            else:
                lr -= 1
            if dy < 0:
                tb += 1
            else:
                tb -= 1
        obj0 = obj1
    if 0 < lr:
        lr = 'lr'
    else:
        lr = 'rl'
    if 0 < tb:
        tb = 'tb'
    else:
        tb = 'bt'
    if 0 < xy:
        return lr+'-'+tb
    else:
        return tb+'-'+lr


##  group_lines
##
def group_lines(groupfunc, objs, findfunc, debug=0):
    """Group LTTextLine objects to form a LTTextBox."""
    plane = Plane(objs)
    groups = {}
    for obj in objs:
        neighbors = findfunc(obj, plane)
        assert obj in neighbors, obj
        members = neighbors[:]
        for obj1 in neighbors:
            if obj1 in groups:
                members.extend(groups.pop(obj1))
        if debug:
            print >>sys.stderr, 'group:', members
        group = groupfunc(list(uniq(members)))
        for obj in members:
            groups[obj] = group
    done = set()
    r = []
    for obj in objs:
        group = groups[obj]
        if group in done: continue
        done.add(group)
        group.fixate()
        r.append(group)
    return r


##  group_boxes
##
def group_boxes(groupfunc, objs, distfunc, debug=0):
    assert objs
    while 2 <= len(objs):
        mindist = INF
        minpair = None
        objs = csort(objs, key=lambda obj: obj.width*obj.height)
        for i in xrange(len(objs)):
            for j in xrange(i+1, len(objs)):
                d = distfunc(objs[i], objs[j])
                if d < mindist:
                    mindist = d
                    minpair = (objs[i], objs[j])
        assert minpair
        (obj1, obj2) = minpair
        objs.remove(obj1)
        objs.remove(obj2)
        if debug:
            print >>sys.stderr, 'group:', obj1, obj2
        objs.append(groupfunc([obj1, obj2]))
    assert len(objs) == 1
    return objs.pop()


##  LTAnalyzer
##
class LTAnalyzer(LTContainer):

    def analyze(self, laparams):
        """Perform the layout analysis."""
        (textobjs, otherobjs) = self.get_textobjs()
        if not laparams or not textobjs: return
        if laparams.writing_mode not in ('lr-tb', 'tb-rl'):
            laparams.writing_mode = guess_wmode(textobjs)
        if (laparams.writing_mode.startswith('tb-') or
            laparams.writing_mode.startswith('bt-')):
            textboxes = self.build_textbox_vertical(textobjs, laparams)
            top = self.group_textbox_tb_rl(textboxes, laparams)
        else:
            textboxes = self.build_textbox_horizontal(textobjs, laparams)
            top = self.group_textbox_lr_tb(textboxes, laparams)
        def assign_index(obj, i):
            if isinstance(obj, LTTextBox):
                obj.index = i
                i += 1
            elif isinstance(obj, LTTextGroup):
                for x in obj:
                    i = assign_index(x, i)
            return i
        assign_index(top, 0)
        textboxes.sort(key=lambda box:box.index)
        self.objs = textboxes + otherobjs
        self.layout = top
        return

    def get_textobjs(self):
        """Split all the objects in the page into text-related objects and others."""
        textobjs = []
        otherobjs = []
        for obj in self.objs:
            if isinstance(obj, LTText) and obj.is_upright():
                textobjs.append(obj)
            else:
                otherobjs.append(obj)
        return (textobjs, otherobjs)

    def build_textbox_horizontal(self, objs, laparams):
        """Identify horizontal text regions in the page."""
        def aligned(obj1, obj2):
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
            if prev is not None and not aligned(prev, cur):
                if line:
                    lines.append(LTTextLineHorizontal(line, laparams.word_margin))
                    line = []
            line.append(cur)
            prev = cur
        if line:
            lines.append(LTTextLineHorizontal(line, laparams.word_margin))
        return group_lines(LTTextBoxHorizontal, lines, 
                           lambda obj, plane: obj.find_neighbors(plane, laparams.line_margin))
    
    def build_textbox_vertical(self, objs, laparams):
        """Identify vertical text regions in the page."""
        def aligned(obj1, obj2):
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
            if prev is not None and not aligned(prev, cur):
                if line:
                    lines.append(LTTextLineVertical(line, laparams.word_margin))
                    line = []
            line.append(cur)
            prev = cur
        if line:
            lines.append(LTTextLineVertical(line, laparams.word_margin))
        return group_lines(LTTextBoxVertical, lines,
                           lambda obj, plane: obj.find_neighbors(plane, laparams.line_margin))

    def group_textbox_lr_tb(self, boxes, laparams):
        def dist(obj1, obj2):
            return ((max(obj1.x1,obj2.x1) - min(obj1.x0,obj2.x0)) * 
                    (max(obj1.y1,obj2.y1) - min(obj1.y0,obj2.y0)) -
                    (obj1.width*obj1.height + obj2.width*obj2.height))
        return group_boxes(LTTextGroupLRTB, boxes, dist)

    def group_textbox_tb_rl(self, boxes, laparams):
        def dist(obj1, obj2):
            return ((max(obj1.x1,obj2.x1) - min(obj1.x0,obj2.x0)) *
                    (max(obj1.y1,obj2.y1) - min(obj1.y0,obj2.y0)) -
                    (obj1.width*obj1.height + obj2.width*obj2.height))
        return group_boxes(LTTextGroupTBRL, boxes, dist)
    

##  LTFigure
##
class LTFigure(LTAnalyzer):

    def __init__(self, name, bbox, matrix):
        (x,y,w,h) = bbox
        bbox = get_bounds( apply_matrix_pt(matrix, (p,q))
                           for (p,q) in ((x,y), (x+w,y), (x,y+h), (x+w,y+h)) )
        LTAnalyzer.__init__(self, bbox)
        self.name = name
        self.matrix = matrix
        return

    def __repr__(self):
        return ('<figure %r bbox=%s matrix=%s>' %
                (self.name, bbox2str(self.bbox), matrix2str(self.matrix)))

    def analyze(self, laparams):
        if laparams.all_texts:
            LTAnalyzer.analyze(self, laparams)
        return


##  LTPage
##
class LTPage(LTAnalyzer):

    def __init__(self, pageid, bbox, rotate=0):
        LTAnalyzer.__init__(self, bbox)
        self.pageid = pageid
        self.rotate = rotate
        self.layout = None
        return

    def __repr__(self):
        return ('<page(%r) bbox=%s rotate=%r>' % (self.pageid, bbox2str(self.bbox), self.rotate))
