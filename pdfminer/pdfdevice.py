#!/usr/bin/env python
import sys
from utils import mult_matrix
from utils import translate_matrix
from pdffont import PDFUnicodeNotDefined


##  PDFDevice
##
class PDFDevice(object):

    debug = 0

    def __init__(self, rsrc):
        self.rsrc = rsrc
        self.ctm = None
        return

    def __repr__(self):
        return '<PDFDevice>'

    def close(self):
        return

    def set_ctm(self, ctm):
        self.ctm = ctm
        return

    def begin_tag(self, tag, props=None):
        return
    def end_tag(self):
        return
    def do_tag(self, tag, props=None):
        return

    def begin_page(self, page, ctm):
        return
    def end_page(self, page):
        return
    def begin_figure(self, name, bbox, matrix):
        return
    def end_figure(self, name):
        return

    def paint_path(self, graphicstate, stroke, fill, evenodd, path):
        return
    def render_image(self, stream, size):
        return
    def render_string(self, textstate, seq):
        return


##  PDFTextDevice
##
class PDFTextDevice(PDFDevice):

    def handle_undefined_char(self, cidcoding, cid):
        if self.debug:
            print >>sys.stderr, 'undefined: %r, %r' % (cidcoding, cid)
        return '?'

    def render_chars(self, matrix, font, fontsize, charspace, scaling, chars):
        return (0, 0)

    def render_string(self, textstate, seq):
        matrix = mult_matrix(textstate.matrix, self.ctm)
        font = textstate.font
        fontsize = textstate.fontsize
        scaling = textstate.scaling * .01
        charspace = textstate.charspace * scaling
        wordspace = textstate.wordspace * scaling
        dxscale = .001 * fontsize * scaling
        chars = []
        needspace = False
        (x,y) = textstate.linematrix
        for obj in seq:
            if isinstance(obj, int) or isinstance(obj, float):
                (dx,dy) = self.render_chars(translate_matrix(matrix, (x,y)), font,
                                            fontsize, charspace, scaling, chars)
                x += dx
                y += dy
                d = -obj*dxscale
                if font.is_vertical():
                    y += d
                else:
                    x += d
                chars = []
                needspace = False
            else:
                for cid in font.decode(obj):
                    try:
                        char = font.to_unichr(cid)
                    except PDFUnicodeNotDefined, e:
                        (cidcoding, cid) = e.args
                        char = self.handle_undefined_char(cidcoding, cid)
                    chars.append((char, cid))
                    if cid == 32 and textstate.wordspace and not font.is_multibyte():
                        if needspace:
                            if font.is_vertical():
                                y += charspace
                            else:
                                x += charspace
                        (dx,dy) = self.render_chars(translate_matrix(matrix, (x,y)), font,
                                                    fontsize, charspace, scaling, chars)
                        needspace = True
                        x += dx
                        y += dy
                        if font.is_vertical():
                            y += wordspace
                        else:
                            x += wordspace
                        chars = []
        if chars:
            if needspace:
                if font.is_vertical():
                    y += charspace
                else:
                    x += charspace
            (dx,dy) = self.render_chars(translate_matrix(matrix, (x,y)), font,
                                        fontsize, charspace, scaling, chars)
            x += dx
            y += dy
        textstate.linematrix = (x,y)
        return
