
from .utils import INF
from .utils import Plane
from .utils import get_bound
from .utils import uniq
from .utils import csort
from .utils import fsplit
from .utils import bbox2str
from .utils import matrix2str
from .utils import apply_matrix_pt

import six # Python 2+3 compatibility

##  IndexAssigner
##
class IndexAssigner(object):

    def __init__(self, index=0):
        self.index = index
        return

    def run(self, obj):
        if isinstance(obj, LTTextBox):
            obj.index = self.index
            self.index += 1
        elif isinstance(obj, LTTextGroup):
            for x in obj:
                self.run(x)
        return


##  LAParams
##
class LAParams(object):

    def __init__(self,
                 line_overlap=0.5,
                 char_margin=2.0,
                 line_margin=0.5,
                 word_margin=0.1,
                 boxes_flow=0.5,
                 detect_vertical=False,
                 all_texts=False):
        self.line_overlap = line_overlap
        self.char_margin = char_margin
        self.line_margin = line_margin
        self.word_margin = word_margin
        self.boxes_flow = boxes_flow
        self.detect_vertical = detect_vertical
        self.all_texts = all_texts
        return

    def __repr__(self):
        return ('<LAParams: char_margin=%.1f, line_margin=%.1f, word_margin=%.1f all_texts=%r>' %
                (self.char_margin, self.line_margin, self.word_margin, self.all_texts))


##  LTItem
##
class LTItem(object):

    def analyze(self, laparams):
        """Perform the layout analysis."""
        return


##  LTText
##
class LTText(object):

    def __repr__(self):
        return ('<%s %r>' %
                (self.__class__.__name__, self.get_text()))

    def get_text(self):
        raise NotImplementedError


##  LTComponent
##
class LTComponent(LTItem):

    def __init__(self, bbox):
        LTItem.__init__(self)
        self.set_bbox(bbox)
        return

    def __repr__(self):
        return ('<%s %s>' %
                (self.__class__.__name__, bbox2str(self.bbox)))

    # Disable comparison.
    def __lt__(self, _):
        raise ValueError
    def __le__(self, _):
        raise ValueError
    def __gt__(self, _):
        raise ValueError
    def __ge__(self, _):
        raise ValueError

    def set_bbox(self, bbox):
        (x0, y0, x1, y1) = bbox
        self.x0 = x0
        self.y0 = y0
        self.x1 = x1
        self.y1 = y1
        self.width = x1-x0
        self.height = y1-y0
        self.bbox = bbox
        return

    def is_empty(self):
        return self.width <= 0 or self.height <= 0

    def is_hoverlap(self, obj):
        assert isinstance(obj, LTComponent), str(type(obj))
        return obj.x0 <= self.x1 and self.x0 <= obj.x1

    def hdistance(self, obj):
        assert isinstance(obj, LTComponent), str(type(obj))
        if self.is_hoverlap(obj):
            return 0
        else:
            return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))

    def hoverlap(self, obj):
        assert isinstance(obj, LTComponent), str(type(obj))
        if self.is_hoverlap(obj):
            return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))
        else:
            return 0

    def is_voverlap(self, obj):
        assert isinstance(obj, LTComponent), str(type(obj))
        return obj.y0 <= self.y1 and self.y0 <= obj.y1

    def vdistance(self, obj):
        assert isinstance(obj, LTComponent), str(type(obj))
        if self.is_voverlap(obj):
            return 0
        else:
            return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))

    def voverlap(self, obj):
        assert isinstance(obj, LTComponent), str(type(obj))
        if self.is_voverlap(obj):
            return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))
        else:
            return 0


##  LTCurve
##
class LTCurve(LTComponent):

    def __init__(self, linewidth, pts, stroke = False, fill = False, evenodd = False, stroking_color = None, non_stroking_color = None):
        LTComponent.__init__(self, get_bound(pts))
        self.pts = pts
        self.linewidth = linewidth
        self.stroke = stroke
        self.fill = fill
        self.evenodd = evenodd
        self.stroking_color = stroking_color
        self.non_stroking_color = non_stroking_color
        return

    def get_pts(self):
        return ','.join('%.3f,%.3f' % p for p in self.pts)


##  LTLine
##
class LTLine(LTCurve):

    def __init__(self, linewidth, p0, p1, stroke = False, fill = False, evenodd = False, stroking_color = None, non_stroking_color = None):
        LTCurve.__init__(self, linewidth, [p0, p1], stroke, fill, evenodd, stroking_color, non_stroking_color)
        return


##  LTRect
##
class LTRect(LTCurve):

    def __init__(self, linewidth, bbox, stroke = False, fill = False, evenodd = False, stroking_color = None, non_stroking_color = None):
        (x0, y0, x1, y1) = bbox
        LTCurve.__init__(self, linewidth, [(x0, y0), (x1, y0), (x1, y1), (x0, y1)], stroke, fill, evenodd, stroking_color, non_stroking_color)
        return


##  LTImage
##
class LTImage(LTComponent):

    def __init__(self, name, stream, bbox):
        LTComponent.__init__(self, bbox)
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
        return ('<%s(%s) %s %r>' %
                (self.__class__.__name__, self.name,
                 bbox2str(self.bbox), self.srcsize))


##  LTAnno
##
class LTAnno(LTItem, LTText):

    def __init__(self, text):
        self._text = text
        return

    def get_text(self):
        return self._text


##  LTChar
##
class LTChar(LTComponent, LTText):

    def __init__(self, matrix, font, fontsize, scaling, rise,
                 text, textwidth, textdisp):
        LTText.__init__(self)
        self._text = text
        self.matrix = matrix
        self.fontname = font.fontname
        self.adv = textwidth * fontsize * scaling
        # compute the boundary rectangle.
        if font.is_vertical():
            # vertical
            width = font.get_width() * fontsize
            (vx, vy) = textdisp
            if vx is None:
                vx = width * 0.5
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
        (a, b, c, d, e, f) = self.matrix
        self.upright = (0 < a*d*scaling and b*c <= 0)
        (x0, y0) = apply_matrix_pt(self.matrix, bll)
        (x1, y1) = apply_matrix_pt(self.matrix, bur)
        if x1 < x0:
            (x0, x1) = (x1, x0)
        if y1 < y0:
            (y0, y1) = (y1, y0)
        LTComponent.__init__(self, (x0, y0, x1, y1))
        if font.is_vertical():
            self.size = self.width
        else:
            self.size = self.height
        return

    def __repr__(self):
        return ('<%s %s matrix=%s font=%r adv=%s text=%r>' %
                (self.__class__.__name__, bbox2str(self.bbox),
                 matrix2str(self.matrix), self.fontname, self.adv,
                 self.get_text()))

    def get_text(self):
        return self._text

    def is_compatible(self, obj):
        """Returns True if two characters can coexist in the same line."""
        return True


##  LTContainer
##
class LTContainer(LTComponent):

    def __init__(self, bbox):
        LTComponent.__init__(self, bbox)
        self._objs = []
        return

    def __iter__(self):
        return iter(self._objs)

    def __len__(self):
        return len(self._objs)

    def add(self, obj):
        self._objs.append(obj)
        return

    def extend(self, objs):
        for obj in objs:
            self.add(obj)
        return

    def analyze(self, laparams):
        for obj in self._objs:
            obj.analyze(laparams)
        return


##  LTExpandableContainer
##
class LTExpandableContainer(LTContainer):

    def __init__(self):
        LTContainer.__init__(self, (+INF, +INF, -INF, -INF))
        return

    def add(self, obj):
        LTContainer.add(self, obj)
        self.set_bbox((min(self.x0, obj.x0), min(self.y0, obj.y0),
                       max(self.x1, obj.x1), max(self.y1, obj.y1)))
        return


##  LTTextContainer
##
class LTTextContainer(LTExpandableContainer, LTText):

    def __init__(self):
        LTText.__init__(self)
        LTExpandableContainer.__init__(self)
        return

    def get_text(self):
        return ''.join(obj.get_text() for obj in self if isinstance(obj, LTText))


##  LTTextLine
##
class LTTextLine(LTTextContainer):

    def __init__(self, word_margin):
        LTTextContainer.__init__(self)
        self.word_margin = word_margin
        return

    def __repr__(self):
        return ('<%s %s %r>' %
                (self.__class__.__name__, bbox2str(self.bbox),
                 self.get_text()))

    def analyze(self, laparams):
        LTTextContainer.analyze(self, laparams)
        LTContainer.add(self, LTAnno('\n'))
        return

    def find_neighbors(self, plane, ratio):
        raise NotImplementedError


class LTTextLineHorizontal(LTTextLine):

    def __init__(self, word_margin):
        LTTextLine.__init__(self, word_margin)
        self._x1 = +INF
        return

    def add(self, obj):
        if isinstance(obj, LTChar) and self.word_margin:
            margin = self.word_margin * max(obj.width, obj.height)
            if self._x1 < obj.x0-margin:
                LTContainer.add(self, LTAnno(' '))
        self._x1 = obj.x1
        LTTextLine.add(self, obj)
        return

    def find_neighbors(self, plane, ratio):
        d = ratio*self.height
        objs = plane.find((self.x0, self.y0-d, self.x1, self.y1+d))
        return [obj for obj in objs
                if (isinstance(obj, LTTextLineHorizontal) and
                    abs(obj.height-self.height) < d and
                    (abs(obj.x0-self.x0) < d or
                     abs(obj.x1-self.x1) < d))]


class LTTextLineVertical(LTTextLine):

    def __init__(self, word_margin):
        LTTextLine.__init__(self, word_margin)
        self._y0 = -INF
        return

    def add(self, obj):
        if isinstance(obj, LTChar) and self.word_margin:
            margin = self.word_margin * max(obj.width, obj.height)
            if obj.y1+margin < self._y0:
                LTContainer.add(self, LTAnno(' '))
        self._y0 = obj.y0
        LTTextLine.add(self, obj)
        return

    def find_neighbors(self, plane, ratio):
        d = ratio*self.width
        objs = plane.find((self.x0-d, self.y0, self.x1+d, self.y1))
        return [obj for obj in objs
                if (isinstance(obj, LTTextLineVertical) and
                    abs(obj.width-self.width) < d and
                    (abs(obj.y0-self.y0) < d or
                     abs(obj.y1-self.y1) < d))]


##  LTTextBox
##
##  A set of text objects that are grouped within
##  a certain rectangular area.
##
class LTTextBox(LTTextContainer):

    def __init__(self):
        LTTextContainer.__init__(self)
        self.index = -1
        return

    def __repr__(self):
        return ('<%s(%s) %s %r>' %
                (self.__class__.__name__,
                 self.index, bbox2str(self.bbox), self.get_text()))


class LTTextBoxHorizontal(LTTextBox):

    def analyze(self, laparams):
        LTTextBox.analyze(self, laparams)
        self._objs = csort(self._objs, key=lambda obj: -obj.y1)
        return

    def get_writing_mode(self):
        return 'lr-tb'


class LTTextBoxVertical(LTTextBox):

    def analyze(self, laparams):
        LTTextBox.analyze(self, laparams)
        self._objs = csort(self._objs, key=lambda obj: -obj.x1)
        return

    def get_writing_mode(self):
        return 'tb-rl'


##  LTTextGroup
##
class LTTextGroup(LTTextContainer):

    def __init__(self, objs):
        LTTextContainer.__init__(self)
        self.extend(objs)
        return


class LTTextGroupLRTB(LTTextGroup):

    def analyze(self, laparams):
        LTTextGroup.analyze(self, laparams)
        # reorder the objects from top-left to bottom-right.
        self._objs = csort(self._objs, key=lambda obj:
                           (1-laparams.boxes_flow)*(obj.x0) -
                           (1+laparams.boxes_flow)*(obj.y0+obj.y1))
        return


class LTTextGroupTBRL(LTTextGroup):

    def analyze(self, laparams):
        LTTextGroup.analyze(self, laparams)
        # reorder the objects from top-right to bottom-left.
        self._objs = csort(self._objs, key=lambda obj:
                           -(1+laparams.boxes_flow)*(obj.x0+obj.x1)
                           - (1-laparams.boxes_flow)*(obj.y1))
        return


##  LTLayoutContainer
##
class LTLayoutContainer(LTContainer):

    def __init__(self, bbox):
        LTContainer.__init__(self, bbox)
        self.groups = None
        return

    # group_objects: group text object to textlines.
    def group_objects(self, laparams, objs):
        obj0 = None
        line = None
        for obj1 in objs:
            if obj0 is not None:
                # halign: obj0 and obj1 is horizontally aligned.
                #
                #   +------+ - - -
                #   | obj0 | - - +------+   -
                #   |      |     | obj1 |   | (line_overlap)
                #   +------+ - - |      |   -
                #          - - - +------+
                #
                #          |<--->|
                #        (char_margin)
                halign = (obj0.is_compatible(obj1) and
                          obj0.is_voverlap(obj1) and
                          (min(obj0.height, obj1.height) * laparams.line_overlap <
                           obj0.voverlap(obj1)) and
                          (obj0.hdistance(obj1) <
                           max(obj0.width, obj1.width) * laparams.char_margin))

                # valign: obj0 and obj1 is vertically aligned.
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
                valign = (laparams.detect_vertical and
                          obj0.is_compatible(obj1) and
                          obj0.is_hoverlap(obj1) and
                          (min(obj0.width, obj1.width) * laparams.line_overlap <
                           obj0.hoverlap(obj1)) and
                          (obj0.vdistance(obj1) <
                           max(obj0.height, obj1.height) * laparams.char_margin))

                if ((halign and isinstance(line, LTTextLineHorizontal)) or
                    (valign and isinstance(line, LTTextLineVertical))):
                    line.add(obj1)
                elif line is not None:
                    yield line
                    line = None
                else:
                    if valign and not halign:
                        line = LTTextLineVertical(laparams.word_margin)
                        line.add(obj0)
                        line.add(obj1)
                    elif halign and not valign:
                        line = LTTextLineHorizontal(laparams.word_margin)
                        line.add(obj0)
                        line.add(obj1)
                    else:
                        line = LTTextLineHorizontal(laparams.word_margin)
                        line.add(obj0)
                        yield line
                        line = None
            obj0 = obj1
        if line is None:
            line = LTTextLineHorizontal(laparams.word_margin)
            line.add(obj0)
        yield line
        return

    # group_textlines: group neighboring lines to textboxes.
    def group_textlines(self, laparams, lines):
        plane = Plane(self.bbox)
        plane.extend(lines)
        boxes = {}
        for line in lines:
            neighbors = line.find_neighbors(plane, laparams.line_margin)
            if line not in neighbors: continue
            members = []
            for obj1 in neighbors:
                members.append(obj1)
                if obj1 in boxes:
                    members.extend(boxes.pop(obj1))
            if isinstance(line, LTTextLineHorizontal):
                box = LTTextBoxHorizontal()
            else:
                box = LTTextBoxVertical()
            for obj in uniq(members):
                box.add(obj)
                boxes[obj] = box
        done = set()
        for line in lines:
            if line not in boxes: continue
            box = boxes[line]
            if box in done:
                continue
            done.add(box)
            if not box.is_empty():
                yield box
        return

    # group_textboxes: group textboxes hierarchically.
    def group_textboxes(self, laparams, boxes):
        assert boxes, str((laparams, boxes))

        def dist(obj1, obj2):
            """A distance function between two TextBoxes.

            Consider the bounding rectangle for obj1 and obj2.
            Return its area less the areas of obj1 and obj2,
            shown as 'www' below. This value may be negative.
                    +------+..........+ (x1, y1)
                    | obj1 |wwwwwwwwww:
                    +------+www+------+
                    :wwwwwwwwww| obj2 |
            (x0, y0) +..........+------+
            """
            x0 = min(obj1.x0, obj2.x0)
            y0 = min(obj1.y0, obj2.y0)
            x1 = max(obj1.x1, obj2.x1)
            y1 = max(obj1.y1, obj2.y1)
            return ((x1-x0)*(y1-y0) - obj1.width*obj1.height - obj2.width*obj2.height)

        def isany(obj1, obj2):
            """Check if there's any other object between obj1 and obj2.
            """
            x0 = min(obj1.x0, obj2.x0)
            y0 = min(obj1.y0, obj2.y0)
            x1 = max(obj1.x1, obj2.x1)
            y1 = max(obj1.y1, obj2.y1)
            objs = set(plane.find((x0, y0, x1, y1)))
            return objs.difference((obj1, obj2))

        def key_obj(t):
            (c,d,_,_) = t
            return (c,d)

        # XXX this still takes O(n^2)  :(
        dists = []
        for i in range(len(boxes)):
            obj1 = boxes[i]
            for j in range(i+1, len(boxes)):
                obj2 = boxes[j]
                dists.append((0, dist(obj1, obj2), obj1, obj2))
        # We could use dists.sort(), but it would randomize the test result.
        dists = csort(dists, key=key_obj)
        plane = Plane(self.bbox)
        plane.extend(boxes)
        while dists:
            (c, d, obj1, obj2) = dists.pop(0)
            if c == 0 and isany(obj1, obj2):
                dists.append((1, d, obj1, obj2))
                continue
            if (isinstance(obj1, (LTTextBoxVertical, LTTextGroupTBRL)) or
                isinstance(obj2, (LTTextBoxVertical, LTTextGroupTBRL))):
                group = LTTextGroupTBRL([obj1, obj2])
            else:
                group = LTTextGroupLRTB([obj1, obj2])
            plane.remove(obj1)
            plane.remove(obj2)
            dists = [ (c,d,obj1,obj2) for (c,d,obj1,obj2) in dists
                      if (obj1 in plane and obj2 in plane) ]
            for other in plane:
                dists.append((0, dist(group, other), group, other))
            dists = csort(dists, key=key_obj)
            plane.add(group)
        assert len(plane) == 1, str(len(plane))
        return list(plane)

    def analyze(self, laparams):
        # textobjs is a list of LTChar objects, i.e.
        # it has all the individual characters in the page.
        (textobjs, otherobjs) = fsplit(lambda obj: isinstance(obj, LTChar), self)
        for obj in otherobjs:
            obj.analyze(laparams)
        if not textobjs:
            return
        textlines = list(self.group_objects(laparams, textobjs))
        (empties, textlines) = fsplit(lambda obj: obj.is_empty(), textlines)
        for obj in empties:
            obj.analyze(laparams)
        textboxes = list(self.group_textlines(laparams, textlines))
        if -1 <= laparams.boxes_flow and laparams.boxes_flow <= +1 and textboxes:
            self.groups = self.group_textboxes(laparams, textboxes)
            assigner = IndexAssigner()
            for group in self.groups:
                group.analyze(laparams)
                assigner.run(group)
            textboxes.sort(key=lambda box: box.index)
        else:
            def getkey(box):
                if isinstance(box, LTTextBoxVertical):
                    return (0, -box.x1, box.y0)
                else:
                    return (1, box.y0, box.x0)
            textboxes.sort(key=getkey)
        self._objs = textboxes + otherobjs + empties
        return


##  LTFigure
##
class LTFigure(LTLayoutContainer):

    def __init__(self, name, bbox, matrix):
        self.name = name
        self.matrix = matrix
        (x, y, w, h) = bbox
        bbox = get_bound(apply_matrix_pt(matrix, (p, q))
                         for (p, q) in ((x, y), (x+w, y), (x, y+h), (x+w, y+h)))
        LTLayoutContainer.__init__(self, bbox)
        return

    def __repr__(self):
        return ('<%s(%s) %s matrix=%s>' %
                (self.__class__.__name__, self.name,
                 bbox2str(self.bbox), matrix2str(self.matrix)))

    def analyze(self, laparams):
        if not laparams.all_texts:
            return
        LTLayoutContainer.analyze(self, laparams)
        return


##  LTPage
##
class LTPage(LTLayoutContainer):

    def __init__(self, pageid, bbox, rotate=0):
        LTLayoutContainer.__init__(self, bbox)
        self.pageid = pageid
        self.rotate = rotate
        return

    def __repr__(self):
        return ('<%s(%r) %s rotate=%r>' %
                (self.__class__.__name__, self.pageid,
                 bbox2str(self.bbox), self.rotate))
