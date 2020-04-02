import heapq
import logging

from .utils import INF
from .utils import Plane
from .utils import apply_matrix_pt
from .utils import bbox2str
from .utils import fsplit
from .utils import get_bound
from .utils import matrix2str
from .utils import uniq

logger = logging.getLogger(__name__)


class IndexAssigner:

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


class LAParams:
    """Parameters for layout analysis

    :param line_overlap: If two characters have more overlap than this they
        are considered to be on the same line. The overlap is specified
        relative to the minimum height of both characters.
    :param char_margin: If two characters are closer together than this
        margin they are considered to be part of the same word. If
        characters are on the same line but not part of the same word, an
        intermediate space is inserted. The margin is specified relative to
        the width of the character.
    :param word_margin: If two words are are closer together than this
        margin they are considered to be part of the same line. A space is
        added in between for readability. The margin is specified relative
        to the width of the word.
    :param line_margin: If two lines are are close together they are
        considered to be part of the same paragraph. The margin is
        specified relative to the height of a line.
    :param boxes_flow: Specifies how much a horizontal and vertical position
        of a text matters when determining the order of text boxes. The value
        should be within the range of -1.0 (only horizontal position
        matters) to +1.0 (only vertical position matters).
    :param cell_margin: (float) An additional distance allowing a line
        to be counted as splitting an object.  When set to None, the
        splitting logic is deactivated.
    :param detect_vertical: If vertical text should be considered during
        layout analysis
    :param all_texts: If layout analysis should be performed on text in
        figures.
    """

    def __init__(self,
                 line_overlap=0.5,
                 char_margin=2.0,
                 line_margin=0.5,
                 word_margin=0.1,
                 boxes_flow=0.5,
                 cell_margin=None,
                 detect_vertical=False,
                 all_texts=False):
        self.line_overlap = line_overlap
        self.char_margin = char_margin
        self.line_margin = line_margin
        self.word_margin = word_margin
        self.cell_margin = cell_margin
        self.boxes_flow = boxes_flow
        self.detect_vertical = detect_vertical
        self.all_texts = all_texts
        return

    def __repr__(self):
        return '<LAParams: char_margin=%.1f, line_margin=%.1f, ' \
               'word_margin=%.1f, cell_margin=%.1f, boxes_flow=%.1f, ' \
               'detect_vertical=%r, all_texts=%r>' % \
               (self.char_margin, self.line_margin, self.word_margin,
                self.cell_margin, self.boxes_flow, self.detect_vertical,
                self.all_texts)


class LTItem:
    """Interface for things that can be analyzed"""

    def analyze(self, laparams):
        """Perform the layout analysis."""
        return


class LTText:
    """Interface for things that have text"""

    def __repr__(self):
        return ('<%s %r>' %
                (self.__class__.__name__, self.get_text()))

    def get_text(self):
        """Text contained in this object"""
        raise NotImplementedError


class LTComponent(LTItem):
    """Object with a bounding box"""

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


class LTCurve(LTComponent):
    """A generic Bezier curve"""

    def __init__(self, linewidth, pts, stroke=False, fill=False, evenodd=False,
                 stroking_color=None, non_stroking_color=None):
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


class LTLine(LTCurve):
    """A single straight line.

    Could be used for separating text or figures.
    """

    def __init__(self,
                 linewidth,
                 p0,
                 p1,
                 stroke=False,
                 fill=False,
                 evenodd=False,
                 stroking_color=None,
                 non_stroking_color=None):
        LTCurve.__init__(self,
                         linewidth,
                         [p0, p1],
                         stroke,
                         fill,
                         evenodd,
                         stroking_color,
                         non_stroking_color)
        return


class LTRect(LTCurve):
    """A rectangle.

    Could be used for framing another pictures or figures.
    """

    def __init__(self,
                 linewidth,
                 bbox,
                 stroke=False,
                 fill=False,
                 evenodd=False,
                 stroking_color=None,
                 non_stroking_color=None):
        (x0, y0, x1, y1) = bbox
        LTCurve.__init__(self,
                         linewidth,
                         [(x0, y0), (x1, y0), (x1, y1), (x0, y1)],
                         stroke,
                         fill,
                         evenodd,
                         stroking_color,
                         non_stroking_color)
        return


class LTImage(LTComponent):
    """An image object.

    Embedded images can be in JPEG, Bitmap or JBIG2.
    """

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


class LTAnno(LTItem, LTText):
    """Actual letter in the text as a Unicode string.

    Note that, while a LTChar object has actual boundaries, LTAnno objects does
    not, as these are "virtual" characters, inserted by a layout analyzer
    according to the relationship between two characters (e.g. a space).
    """

    def __init__(self, text):
        self._text = text
        return

    def get_text(self):
        return self._text


class LTChar(LTComponent, LTText):
    """Actual letter in the text as a Unicode string."""

    def __init__(self, matrix, font, fontsize, scaling, rise,
                 text, textwidth, textdisp, ncs, graphicstate):
        LTText.__init__(self)
        self._text = text
        self.matrix = matrix
        self.fontname = font.fontname
        self.ncs = ncs
        self.graphicstate = graphicstate
        self.adv = textwidth * fontsize * scaling
        # compute the boundary rectangle.
        if font.is_vertical():
            # vertical
            (vx, vy) = textdisp
            if vx is None:
                vx = fontsize * 0.5
            else:
                vx = vx * fontsize * .001
            vy = (1000 - vy) * fontsize * .001
            bbox_lower_left = (-vx, vy + rise + self.adv)
            bbox_upper_right = (-vx + fontsize, vy + rise)
        else:
            # horizontal
            descent = font.get_descent() * fontsize
            bbox_lower_left = (0, descent + rise)
            bbox_upper_right = (self.adv, descent + rise + fontsize)
        (a, b, c, d, e, f) = self.matrix
        self.upright = (0 < a*d*scaling and b*c <= 0)
        (x0, y0) = apply_matrix_pt(self.matrix, bbox_lower_left)
        (x1, y1) = apply_matrix_pt(self.matrix, bbox_upper_right)
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


class LTContainer(LTComponent):
    """Object that can be extended and analyzed"""

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


class LTExpandableContainer(LTContainer):
    def __init__(self):
        LTContainer.__init__(self, (+INF, +INF, -INF, -INF))
        return

    def add(self, obj):
        LTContainer.add(self, obj)
        self.set_bbox((min(self.x0, obj.x0), min(self.y0, obj.y0),
                       max(self.x1, obj.x1), max(self.y1, obj.y1)))
        return


class LTTextContainer(LTExpandableContainer, LTText):
    def __init__(self):
        LTText.__init__(self)
        LTExpandableContainer.__init__(self)
        return

    def get_text(self):
        return ''.join(obj.get_text() for obj in self
                       if isinstance(obj, LTText))


class LTTextLine(LTTextContainer):
    """Contains a list of LTChar objects that represent a single text line.

    The characters are aligned either horizontally or vertically, depending on
    the text's writing mode.
    """

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


class LTTextBox(LTTextContainer):
    """Represents a group of text chunks in a rectangular area.

    Note that this box is created by geometric analysis and does not
    necessarily represents a logical boundary of the text. It contains a list
    of LTTextLine objects.
    """

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
        self._objs.sort(key=lambda obj: -obj.y1)
        return

    def get_writing_mode(self):
        return 'lr-tb'


class LTTextBoxVertical(LTTextBox):
    def analyze(self, laparams):
        LTTextBox.analyze(self, laparams)
        self._objs.sort(key=lambda obj: -obj.x1)
        return

    def get_writing_mode(self):
        return 'tb-rl'


class LTTextGroup(LTTextContainer):
    def __init__(self, objs):
        LTTextContainer.__init__(self)
        self.extend(objs)
        return


class LTTextGroupLRTB(LTTextGroup):
    def analyze(self, laparams):
        LTTextGroup.analyze(self, laparams)
        # reorder the objects from top-left to bottom-right.
        self._objs.sort(
            key=lambda obj: (1 - laparams.boxes_flow) * obj.x0
            - (1 + laparams.boxes_flow) * (obj.y0 + obj.y1))
        return


class LTTextGroupTBRL(LTTextGroup):
    def analyze(self, laparams):
        LTTextGroup.analyze(self, laparams)
        # reorder the objects from top-right to bottom-left.
        self._objs.sort(
            key=lambda obj: - (1 + laparams.boxes_flow) * (obj.x0 + obj.x1)
                            - (1 - laparams.boxes_flow) * obj.y1)
        return


class LTLayoutContainer(LTContainer):
    def __init__(self, bbox):
        LTContainer.__init__(self, bbox)
        self.groups = None
        return

    def are_split_horizontally(self, obj0, obj1, splitobjs, cell_margin):
        """ detect that between obj0 and obj1 there is a horizontal
        split line.

        :param obj0: a LTTextLineHorizontal, LTTextLineVertical, or
            LTChar Object
        :param obj1: a LTTextLineHorizontal, LTTextLineVertical, or
            LTChar Object
        :param splitobjs: list -- each elememnt is a LTLine Object
        :param cell_margin: float -- the distance given for allowing
                additional matches
        :return: boolean if a splitting line is found between obj0 and
            obj1 in splitobjs
        """
        cross = False

        # define some convience constants (for speed)
        largest_x0 = max(obj0.x0, obj1.x0)
        smallest_x1 = min(obj0.x1, obj1.x1)
        
        min_y = min(obj0.y0, obj1.y0) - cell_margin
        max_y = max(obj0.y1, obj1.y1) + cell_margin

        for r in splitobjs:
            # if the split object covers over the overlap of the projected
            # width of the combined objects
            full_overlap = ((r.x0 <= largest_x0)
                            and (r.x1 >= smallest_x1))

            if full_overlap:
                # look to see if the y coordinates cross the bounding box
                # of the two objects
                if ((r.y0 >= min_y and r.y0 <= max_y)
                        or (r.y1 >= min_y and r.y1 <= max_y)):
                    cross = True
                    break
        return cross

    def are_split_vertically(self, obj0, obj1, splitobjs, cell_margin):
        """ detects if between obj0 and obj1, there is a vertical split
        line

        :param obj0: a LTTextLineHorizontal, LTTextLineVertical, or
            LTChar Object
        :param obj1: a LTTextLineHorizontal, LTTextLineVertical, or
            LTChar Object
        :param splitobs: list -- list of LTLine based objects that will 
            be used to verify that obj1 and obj2 are divided 
        :param cell_margin: float -- the distance one cell is allowed to
            overlap horizontally
        :return: boolean if a splitting line is found between obj0 and
            obj1 in splitobjs
        """
        cross = False

        # define some convience constants (for speed)
        largest_y0 = max(obj0.y0, obj1.y0)
        smallest_y1 = min(obj0.y1, obj1.y1)
        
        min_x = min(obj0.x0, obj1.x0) - cell_margin
        max_x = max(obj0.x1, obj1.x1) + cell_margin

        for r in splitobjs:
            # if the split object covers over the overlap of the projected
            # height of the combined objects
            full_overlap = ((r.y0 <= largest_y0)
                            and (r.y1 >= smallest_y1))

            if full_overlap:
                # look to see if the x coordinates cross the bounding box
                # of the two objects
                if ((r.x0 >= min_x and r.x0 <= max_x)
                        or (r.x1 >= min_x and r.x1 <= max_x)):
                    cross = True
                    break

        return cross

    def group_objects(self, laparams, objs, splitobjs):
        """ group text object to textlines.

        :param laparams:  LaParams object - contains all the settings
            for determing the page layout
        :param objs: list - each element is a unique LTChar object
        :param splitobjs: list - each element is a LTRect object.  These
            are used as barriers to prevent joining into textlines
        :return: Textline object
        """
        obj0 = None
        line = None
        for obj1 in objs:
            if obj0 is not None:
                # halign: obj0 and obj1 are horizontally aligned. (boolean)
                #
                #   +------+ - - -
                #   | obj0 | - - +------+   -
                #   |      |     | obj1 |   | (line_overlap)
                #   +------+ - - |      |   -
                #          - - - +------+
                #
                #          |<--->|
                #        (char_margin)
                halign = (
                    obj0.is_compatible(obj1) and
                    obj0.is_voverlap(obj1) and
                    (min(obj0.height, obj1.height) * laparams.line_overlap <
                        obj0.voverlap(obj1)) and
                    (obj0.hdistance(obj1) <
                        max(obj0.width, obj1.width) * laparams.char_margin)
                    and (laparams.cell_margin is None
                         or not self.are_split_vertically(obj0,
                                                          obj1,
                                                          splitobjs,
                                                          laparams.cell_margin)
                    )
                )

                # valign: obj0 and obj1 are vertically aligned. (boolean)
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
                valign = (
                    laparams.detect_vertical
                    and obj0.is_compatible(obj1)
                    and obj0.is_hoverlap(obj1)
                    and (
                         min(obj0.width, obj1.width) * laparams.line_overlap
                         < obj0.hoverlap(obj1)
                    )
                    and (
                         obj0.vdistance(obj1)
                         < max(obj0.height, obj1.height) * laparams.char_margin
                    )
                    and (laparams.cell_margin is None or
                         not self.are_split_horizontally(obj0,
                                                         obj1,
                                                         splitobjs,
                                                         laparams.cell_margin))
                )

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
    def group_textlines(self, laparams, lines, splitobjs=[]):
        """ group_textlines: group neighboring lines to textboxes

        :param laparams: laparams obj -- an object containing all the
            parameters needed to join together characters and make lines
            of text
        :param lines: list -- each member is an LTLayoutContainer object
            containing a unique textline
        :param splitobjs: list -- each member is an LTRect object
        """
        plane = Plane(self.bbox)
        plane.extend(lines)
        boxes = {}
        # iterate through all neighbors and join any that are text that
        # pass requirements
        for line in lines:
            neighbors = line.find_neighbors(plane, laparams.line_margin)
            if line not in neighbors:
                continue
            members = []
            for obj1 in neighbors:
                not_split_flag = True
                # for each text line to be merged, see if it is split by
                # an LTLine object
                if line is not obj1 and splitobjs:
                    if (self.are_split_vertically(line,
                                                  obj1,
                                                  splitobjs,
                                                  laparams.cell_margin)
                        or self.are_split_horizontally(line,
                                                       obj1,
                                                       splitobjs,
                                                       laparams.cell_margin)):
                        not_split_flag = False
                
                if not_split_flag:
                    members.append(obj1)

                    # verify that the neighbor isn't apart of anoter text box
                    # if it is add the entire textbox
                    if obj1 in boxes:
                        members.extend(boxes.pop(obj1))

            # instantiate a new textbox
            if isinstance(line, LTTextLineHorizontal):
                box = LTTextBoxHorizontal()
            else:
                box = LTTextBoxVertical()

            # Add unique textlines to the textbox and record that its been
            # added (so we don't add the textline to two different boxes)
            for obj in uniq(members):
                box.add(obj)
                boxes[obj] = box
        done = set()

        # yield each non-empty textbox.
        for line in lines:
            if line not in boxes:
                continue
            box = boxes[line]
            if box in done:
                continue
            done.add(box)
            if not box.is_empty():
                yield box
        return

    def group_textboxes(self, laparams, boxes):
        """Group textboxes hierarchically.

        Get pair-wise distances, via dist func defined below, and then merge
        from the closest textbox pair. Once obj1 and obj2 are merged /
        grouped, the resulting group is considered as a new object, and its
        distances to other objects & groups are added to the process queue.

        For performance reason, pair-wise distances and object pair info are
        maintained in a heap of (idx, dist, id(obj1), id(obj2), obj1, obj2)
        tuples. It ensures quick access to the smallest element. Note that
        since comparison operators, e.g., __lt__, are disabled for
        LTComponent, id(obj) has to appear before obj in element tuples.

        :param laparams: LAParams object.
        :param boxes: All textbox objects to be grouped.
        :return: a list that has only one element, the final top level textbox.
        """

        # Add unique lines to the textbox
        def dist(obj1, obj2):
            """A distance function between two TextBoxes.

            Consider the bounding rectangle for obj1 and obj2.
            Return its area less the areas of obj1 and obj2,
            shown as 'www' below. This value may be negative.
                    +------+..........+ (x1, y1)
                    | obj1 |wwwwwwwwww:
                    +------+www+------+
                    :wwwwwwwwww| obj2 |
            (x0, y0)+..........+------+
            """
            x0 = min(obj1.x0, obj2.x0)
            y0 = min(obj1.y0, obj2.y0)
            x1 = max(obj1.x1, obj2.x1)
            y1 = max(obj1.y1, obj2.y1)
            return ((x1-x0)*(y1-y0)
                    - obj1.width*obj1.height
                    - obj2.width*obj2.height)

        def isany(obj1, obj2):
            """Check if there's any other object between obj1 and obj2."""
            x0 = min(obj1.x0, obj2.x0)
            y0 = min(obj1.y0, obj2.y0)
            x1 = max(obj1.x1, obj2.x1)
            y1 = max(obj1.y1, obj2.y1)
            objs = set(plane.find((x0, y0, x1, y1)))
            return objs.difference((obj1, obj2))

        dists = []
        for i in range(len(boxes)):
            obj1 = boxes[i]
            for j in range(i+1, len(boxes)):
                obj2 = boxes[j]
                dists.append((False, dist(obj1, obj2), id(obj1), id(obj2),
                              obj1, obj2))
        heapq.heapify(dists)

        plane = Plane(self.bbox)
        plane.extend(boxes)
        done = set()
        while len(dists) > 0:
            (skip_isany, d, id1, id2, obj1, obj2) = heapq.heappop(dists)
            # Skip objects that are already merged
            if (id1 not in done) and (id2 not in done):
                if skip_isany and isany(obj1, obj2):
                    heapq.heappush(dists, (True, d, id1, id2, obj1, obj2))
                    continue
                if isinstance(obj1, (LTTextBoxVertical, LTTextGroupTBRL)) or \
                        isinstance(obj2, (LTTextBoxVertical, LTTextGroupTBRL)):
                    group = LTTextGroupTBRL([obj1, obj2])
                else:
                    group = LTTextGroupLRTB([obj1, obj2])
                plane.remove(obj1)
                plane.remove(obj2)
                done.update([id1, id2])

                for other in plane:
                    heapq.heappush(dists, (False, dist(group, other),
                                           id(group), id(other), group, other))
                plane.add(group)
        return list(plane)

    def analyze(self, laparams):
        """ used recursively to split object into smaller objects

        :param laparams: an LAParams object containing all the revelvant
            parameters for assessing the broken down pdf
        """
        # textobjs is a list of LTChar objects, i.e.
        # it has all the individual characters in the page.
        (textobjs, otherobjs) = fsplit(lambda obj: isinstance(obj, LTChar),
                                       self)
        if laparams.cell_margin is not None:
            (splitobjs, otherobjs) = (
                fsplit(lambda obj: (isinstance(obj, LTRect)
                                    | isinstance(obj, LTLine)
                                    | isinstance(obj, LTCurve)), self)
            )
        else:
            splitobjs = []
        for obj in otherobjs:
            obj.analyze(laparams)
        if not textobjs:
            return
        textlines = list(self.group_objects(laparams, textobjs, splitobjs))
        (empties, textlines) = fsplit(lambda obj: obj.is_empty(), textlines)
        for obj in empties:
            obj.analyze(laparams)
        textboxes = list(self.group_textlines(laparams, textlines, splitobjs))
        if (-1 <= laparams.boxes_flow and laparams.boxes_flow <= +1
                and textboxes):
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
        self._objs = textboxes + otherobjs + empties + splitobjs
        return


class LTFigure(LTLayoutContainer):
    """Represents an area used by PDF Form objects.

    PDF Forms can be used to present figures or pictures by embedding yet
    another PDF document within a page. Note that LTFigure objects can appear
    recursively.
    """

    def __init__(self, name, bbox, matrix):
        self.name = name
        self.matrix = matrix
        (x, y, w, h) = bbox
        bounds = ((x, y), (x + w, y), (x, y + h), (x + w, y + h))
        bbox = get_bound(apply_matrix_pt(matrix, (p, q)) for (p, q) in bounds)
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


class LTPage(LTLayoutContainer):
    """Represents an entire page.

    May contain child objects like LTTextBox, LTFigure, LTImage, LTRect,
    LTCurve and LTLine.
    """

    def __init__(self, pageid, bbox, rotate=0):
        LTLayoutContainer.__init__(self, bbox)
        self.pageid = pageid
        self.rotate = rotate
        return

    def __repr__(self):
        return ('<%s(%r) %s rotate=%r>' %
                (self.__class__.__name__, self.pageid,
                 bbox2str(self.bbox), self.rotate))
