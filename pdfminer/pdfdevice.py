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
    def render_image(self, name, stream):
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

    def render_string(self, textstate, seq):
        matrix = mult_matrix(textstate.matrix, self.ctm)
        font = textstate.font
        fontsize = textstate.fontsize
        scaling = textstate.scaling * .01
        charspace = textstate.charspace * scaling
        wordspace = textstate.wordspace * scaling
        if font.is_multibyte():
            wordspace = 0
        dxscale = .001 * fontsize * scaling
        if font.is_vertical():
            textstate.linematrix = self.render_string_vertical(
                seq, matrix, textstate.linematrix, font, fontsize, scaling, charspace, wordspace, dxscale)
        else:
            textstate.linematrix = self.render_string_horizontal(
                seq, matrix, textstate.linematrix, font, fontsize, scaling, charspace, wordspace, dxscale)
        return
    
    def render_string_horizontal(self, seq, matrix, (x,y), 
                                 font, fontsize, scaling, charspace, wordspace, dxscale):
        needcharspace = False
        for obj in seq:
            if isinstance(obj, int) or isinstance(obj, float):
                x -= obj*dxscale
                needcharspace = False
            else:
                for cid in font.decode(obj):
                    if needcharspace:
                        x += charspace
                    x += self.render_char(translate_matrix(matrix, (x,y)),
                                          font, fontsize, scaling, cid)
                    needcharspace = True
                    if cid == 32 and wordspace:
                        x += wordspace
        return (x, y)

    def render_string_vertical(self, seq, matrix, (x,y), 
                               font, fontsize, scaling, charspace, wordspace, dxscale):
        needcharspace = False
        for obj in seq:
            if isinstance(obj, int) or isinstance(obj, float):
                y -= obj*dxscale
                needcharspace = False
            else:
                for cid in font.decode(obj):
                    if needcharspace:
                        y += charspace
                    y += self.render_char(translate_matrix(matrix, (x,y)), 
                                          font, fontsize, scaling, cid)
                    needcharspace = True
                    if cid == 32 and wordspace:
                        y += wordspace
        return (x, y)

    def render_char(self, matrix, font, fontsize, scaling, cid):
        return 0
