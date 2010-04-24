#!/usr/bin/env python
import sys
from utils import mult_matrix
from utils import translate_matrix
from pdffont import PDFUnicodeNotDefined


##  PDFDevice
##
class PDFDevice(object):

    debug = 0

    def __init__(self, rsrcmgr):
        self.rsrcmgr = rsrcmgr
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
                needcharspace = True
            else:
                for cid in font.decode(obj):
                    if needcharspace:
                        x += charspace
                    x += self.render_char(translate_matrix(matrix, (x,y)),
                                          font, fontsize, scaling, cid)
                    if cid == 32 and wordspace:
                        x += wordspace
                    needcharspace = True
        return (x, y)

    def render_string_vertical(self, seq, matrix, (x,y), 
                               font, fontsize, scaling, charspace, wordspace, dxscale):
        needcharspace = False
        for obj in seq:
            if isinstance(obj, int) or isinstance(obj, float):
                y -= obj*dxscale
                needcharspace = True
            else:
                for cid in font.decode(obj):
                    if needcharspace:
                        y += charspace
                    y += self.render_char(translate_matrix(matrix, (x,y)), 
                                          font, fontsize, scaling, cid)
                    if cid == 32 and wordspace:
                        y += wordspace
                    needcharspace = True
        return (x, y)

    def render_char(self, matrix, font, fontsize, scaling, cid):
        return 0


##  TagExtractor
##
class TagExtractor(PDFDevice):

    def __init__(self, rsrcmgr, outfp, codec='utf-8'):
        PDFDevice.__init__(self, rsrcmgr)
        self.outfp = outfp
        self.codec = codec
        self.pageno = 0
        self.tag = None
        return

    def render_string(self, textstate, seq):
        font = textstate.font
        text = ''
        for obj in seq:
            if not isinstance(obj, str): continue
            chars = font.decode(obj)
            for cid in chars:
                try:
                    char = font.to_unichr(cid)
                    text += char
                except PDFUnicodeNotDefined:
                    pass
        self.outfp.write(enc(text, self.codec))
        return

    def begin_page(self, page, ctm):
        self.outfp.write('<page id="%s" bbox="%s" rotate="%d">' %
                         (self.pageno, bbox2str(page.mediabox), page.rotate))
        return

    def end_page(self, page):
        self.outfp.write('</page>\n')
        self.pageno += 1
        return

    def begin_tag(self, tag, props=None):
        s = ''
        if props:
            s = ''.join( ' %s="%s"' % (enc(k), enc(str(v))) for (k,v)
                         in sorted(props.iteritems()) )
        self.outfp.write('<%s%s>' % (enc(tag.name), s))
        self.tag = tag
        return

    def end_tag(self):
        assert self.tag
        self.outfp.write('</%s>' % enc(self.tag.name))
        self.tag = None
        return

    def do_tag(self, tag, props=None):
        self.begin_tag(tag, props)
        self.tag = None
        return
