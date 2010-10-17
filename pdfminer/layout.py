#!/usr/bin/env python
import sys
from sys import maxint as INF
from utils import apply_matrix_pt
from utils import bsearch, bbox2str, matrix2str
from pdffont import PDFUnicodeNotDefined



##  get_bounds
##
def get_bounds(pts):
    """Compute a minimal rectangle that covers all the points."""
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
        self.pts = pts
        self.linewidth = linewidth
        LTItem.__init__(self, get_bounds(pts))
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
        self.adv = font.char_width(cid) * fontsize * scaling
        try:
            text = font.to_unichr(cid)
            assert isinstance(text, unicode), text
        except PDFUnicodeNotDefined:
            text = '?'
        LTText.__init__(self, text)
        # compute the boundary rectangle.
        if self.font.is_vertical():
            # vertical
            width = font.get_width() * fontsize
            (vx,vy) = font.char_disp(cid)
            if vx is None:
                vx = width/2
            else:
                vx = vx * fontsize * .001
            vy = (1000 - vy) * fontsize * .001
            tx = -vx
            ty = vy + rise
            bll = (tx, ty+self.adv)
            bur = (tx+width, ty)
        else:
            # horizontal
            height = font.get_height() * fontsize
            descent = font.get_descent() * fontsize
            ty = descent + rise
            bll = (0, ty)
            bur = (self.adv, ty+height)
        (a,b,c,d,e,f) = self.matrix
        self.upright = (0 < a*d*scaling and b*c <= 0)
        bbox = (apply_matrix_pt(self.matrix, bll) +
                apply_matrix_pt(self.matrix, bur))
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
        return self.font.is_vertical()

    def is_upright(self):
        return self.upright

    
##  LTContainer
##
class LTContainer(LTItem):

    def __init__(self, objs=None, bbox=(0,0,0,0)):
        LTItem.__init__(self, bbox)
        if objs:
            self._objs = objs[:]
        else:
            self._objs = []
        return

    def __repr__(self):
        return ('<container %s>' % bbox2str(self.bbox))

    def __iter__(self):
        return iter(self.get_objs())

    def __len__(self):
        return len(self.get_objs())

    def add(self, obj):
        self._objs.append(obj)
        return

    def merge(self, container):
        self._objs.extend(container._objs)
        return

    def get_objs(self):
        return self._objs

    # fixate(): determines its boundery.
    def fixate(self):
        if not self.width and self._objs:
            (bx0, by0, bx1, by1) = (INF, INF, -INF, -INF)
            for obj in self._objs:
                bx0 = min(bx0, obj.x0)
                by0 = min(by0, obj.y0)
                bx1 = max(bx1, obj.x1)
                by1 = max(by1, obj.y1)
            self.set_bbox((bx0, by0, bx1, by1))
        return


##  LTTextLine
##
class LTTextLine(LTContainer):

    def __init__(self, word_margin=0):
        self.word_margin = word_margin
        LTContainer.__init__(self)
        return

    def __repr__(self):
        return ('<textline %s>' % bbox2str(self.bbox))

    def get_text(self):
        return ''.join( obj.text for obj in self.get_objs() if isinstance(obj, LTText) )

    def find_neighbors(self, plane, ratio):
        raise NotImplementedError

class LTTextLineHorizontal(LTTextLine):

    def __repr__(self):
        return ('<textline-h %s>' % bbox2str(self.bbox))

    def get_objs(self):
        x1 = INF
        for obj in csort(self._objs, key=lambda obj: obj.x0):
            if isinstance(obj, LTChar) and self.word_margin:
                margin = self.word_margin * obj.width
                if x1 < obj.x0-margin:
                    yield LTAnon(' ')
            yield obj
            x1 = obj.x1
        yield LTAnon('\n')
        return

    def find_neighbors(self, plane, ratio):
        h = ratio*self.height
        objs = plane.find((self.x0, self.y0-h, self.x1, self.y1+h))
        return [ obj for obj in objs if isinstance(obj, LTTextLineHorizontal) ]
    
class LTTextLineVertical(LTTextLine):

    def __repr__(self):
        return ('<textline-v %s>' % bbox2str(self.bbox))

    def get_objs(self):
        y0 = -INF
        for obj in csort(self._objs, key=lambda obj: -obj.y1):
            if isinstance(obj, LTChar) and self.word_margin:
                margin = self.word_margin * obj.height
                if obj.y1+margin < y0:
                    yield LTAnon(' ')
            yield obj
            y0 = obj.y0
        yield LTAnon('\n')
        return

    def find_neighbors(self, plane, ratio):
        w = ratio*self.width
        objs = plane.find((self.x0-w, self.y0, self.x1+w, self.y1))
        return [ obj for obj in objs if isinstance(obj, LTTextLineVertical) ]
    

##  LTTextBox
##
##  A set of text objects that are grouped within
##  a certain rectangular area.
##
class LTTextBox(LTContainer):

    def __init__(self, objs):
        LTContainer.__init__(self, objs=objs)
        self.index = None
        return

    def __repr__(self):
        return ('<textbox(%s) %s %r...>' % (self.index, bbox2str(self.bbox), self.get_text()[:20]))

    def get_text(self):
        return ''.join( obj.get_text() for obj in self.get_objs() if isinstance(obj, LTTextLine) )

class LTTextBoxHorizontal(LTTextBox):
    
    def get_objs(self):
        return csort(self._objs, key=lambda obj: -obj.y1)

class LTTextBoxVertical(LTTextBox):

    def get_objs(self):
        return csort(self._objs, key=lambda obj: -obj.x1)


##  LTTextGroup
##
class LTTextGroup(LTContainer):

    def __init__(self, objs):
        LTContainer.__init__(self, objs=objs)
        LTContainer.fixate(self)
        return

class LTTextGroupLRTB(LTTextGroup):
    
    def get_objs(self):
        # reorder the objects from top-left to bottom-right.
        return csort(self._objs, key=lambda obj: obj.x0+obj.x1-(obj.y0+obj.y1))

class LTTextGroupTBRL(LTTextGroup):
    
    def get_objs(self):
        # reorder the objects from top-right to bottom-left.
        return csort(self._objs, key=lambda obj: -(obj.x0+obj.x1)-(obj.y0+obj.y1))


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


##  LTAnalyzer
##
class LTAnalyzer(LTContainer):

    def analyze(self, laparams=None):
        """Perform the layout analysis."""
        if laparams is None: return
        # textobjs is a list of LTChar objects, i.e.
        # it has all the individual characters in the page.
        (textobjs, otherobjs) = self.get_textobjs(self._objs, laparams)
        if not textobjs: return
        textlines = list(self.get_textlines(textobjs, laparams))
        assert sum( len(line._objs) for line in textlines ) == len(textobjs)
        textboxes = list(self.get_textboxes(textlines, laparams))
        assert sum( len(box._objs) for box in textboxes ) == len(textlines)
        top = self.group_textboxes(textboxes, laparams)
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
        self._objs = textboxes + otherobjs
        self.layout = top
        return

    def get_textobjs(self, objs, laparams):
        """Split all the objects in the page into text-related objects and others."""
        textobjs = []
        otherobjs = []
        for obj in objs:
            if isinstance(obj, LTText) and obj.is_upright():
                textobjs.append(obj)
            else:
                otherobjs.append(obj)
        return (textobjs, otherobjs)

    def get_textlines(self, objs, laparams):
        obj0 = None
        line = None
        for obj1 in objs:
            if obj0 is None:
                obj0 = obj1
            else:
                k = 0
                if (obj0.is_voverlap(obj1) and
                    min(obj0.height, obj1.height) * laparams.line_overlap < obj0.voverlap(obj1) and
                    obj0.hdistance(obj1) < min(obj0.width, obj1.width) * laparams.char_margin):
                    # obj0 and obj1 is horizontally aligned:
                    #
                    #   +------+ - - -
                    #   | obj0 | - - +------+   -
                    #   |      |     | obj1 |   | (line_overlap)
                    #   +------+ - - |      |   -
                    #          - - - +------+
                    #
                    #          |<--->|
                    #        (char_margin)
                    k |= 1
                if (obj0.is_hoverlap(obj1) and
                    min(obj0.width, obj1.width) * laparams.line_overlap < obj0.hoverlap(obj1) and
                    obj0.vdistance(obj1) < min(obj0.height, obj1.height) * laparams.char_margin):
                    # obj0 and obj1 is vertically aligned:
                    #
                    #   +------+
                    #   | obj0 |
                    #   |      |
                    #   +------+ - - -
                    #     |    |     | (char_margin)
                    #     +------+ - -
                    #     | obj1 |
                    #     |      |
                    #     +------+
                    #
                    #     |<-->|
                    #   (line_overlap)
                    k |= 2
                if ( (k & 1 and isinstance(line, LTTextLineHorizontal)) or
                     (k & 2 and isinstance(line, LTTextLineVertical)) ):
                    line.add(obj1)
                elif line is None:
                    if k == 2:
                        line = LTTextLineVertical(laparams.word_margin)
                    else:
                        line = LTTextLineHorizontal(laparams.word_margin)
                    line.add(obj0)
                    line.add(obj1)
                else:
                    line.fixate()
                    yield line
                    line = None
                obj0 = obj1
        if line is None:
            line = LTTextLineHorizontal(laparams.word_margin)
            if obj0 is not None:
                line.add(obj0)
        line.fixate()
        yield line
        return

    def get_textboxes(self, lines, laparams):
        plane = Plane(lines)
        groups = {}
        for line in lines:
            neighbors = line.find_neighbors(plane, laparams.line_margin)
            assert line in neighbors, line
            members = neighbors[:]
            for obj1 in neighbors:
                if obj1 in groups:
                    members.extend(groups.pop(obj1))
            members = list(uniq(members))
            if isinstance(line, LTTextLineHorizontal):
                group = LTTextBoxHorizontal(members)
            else:
                group = LTTextBoxVertical(members)
            for obj in members:
                groups[obj] = group
        done = set()
        for line in lines:
            group = groups[line]
            if group in done: continue
            done.add(group)
            group.fixate()
            yield group
        return

    def group_textboxes(self, textboxes, laparams):
        def dist(obj1, obj2):
            """A distance function between two TextBoxes.
            
            Consider the bounding rectangle for obj1 and obj2.
            Return its area less the areas of obj1 and obj2, 
            shown as 'www' below. This value may be negative.
            +------+..........+
            | obj1 |wwwwwwwwww:
            +------+www+------+
            :wwwwwwwwww| obj2 |
            +..........+------+
            """
            return ((max(obj1.x1,obj2.x1) - min(obj1.x0,obj2.x0)) * 
                    (max(obj1.y1,obj2.y1) - min(obj1.y0,obj2.y0)) -
                    (obj1.width*obj1.height + obj2.width*obj2.height))
        textboxes = textboxes[:]
        while 2 <= len(textboxes):
            mindist = INF
            minpair = None
            textboxes = csort(textboxes, key=lambda obj: obj.width*obj.height)
            for i in xrange(len(textboxes)):
                for j in xrange(i+1, len(textboxes)):
                    (obj1, obj2) = (textboxes[i], textboxes[j])
                    d = dist(obj1, obj2)
                    if d < mindist:
                        mindist = d
                        minpair = (obj1, obj2)
            assert minpair
            (obj1, obj2) = minpair
            textboxes.remove(obj1)
            textboxes.remove(obj2)
            if isinstance(obj1, LTTextBoxHorizontal):
                group = LTTextGroupLRTB([obj1, obj2])
            else:
                group = LTTextGroupTBRL([obj1, obj2])
            textboxes.append(group)
        assert len(textboxes) == 1
        return textboxes.pop()
    

##  LTFigure
##
class LTFigure(LTAnalyzer):

    def __init__(self, name, bbox, matrix):
        self.name = name
        self.matrix = matrix
        (x,y,w,h) = bbox
        bbox = get_bounds( apply_matrix_pt(matrix, (p,q))
                           for (p,q) in ((x,y), (x+w,y), (x,y+h), (x+w,y+h)) )
        LTAnalyzer.__init__(self, bbox=bbox)
        return

    def __repr__(self):
        return ('<figure %r bbox=%s matrix=%s>' %
                (self.name, bbox2str(self.bbox), matrix2str(self.matrix)))

    def analyze(self, laparams=None):
        if laparams is not None and laparams.all_texts:
            LTAnalyzer.analyze(self, laparams=laparams)
        return


##  LTPage
##
class LTPage(LTAnalyzer):

    def __init__(self, pageid, bbox, rotate=0):
        LTAnalyzer.__init__(self, bbox=bbox)
        self.pageid = pageid
        self.rotate = rotate
        self.layout = None
        return

    def __repr__(self):
        return ('<page(%r) bbox=%s rotate=%r>' % (self.pageid, bbox2str(self.bbox), self.rotate))
