#!/usr/bin/env python
import sys
from pdfdevice import PDFDevice, PDFTextDevice
from pdffont import PDFUnicodeNotDefined
from layout import LayoutContainer
from layout import LTPage, LTText, LTLine, LTRect, LTPolygon
from layout import LTFigure, LTTextItem, LTTextBox, LTTextLine
from utils import enc
from utils import apply_matrix_pt, mult_matrix


##  TagExtractor
##
class TagExtractor(PDFDevice):

    def __init__(self, rsrc, outfp, codec='utf-8'):
        PDFDevice.__init__(self, rsrc)
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
        (x0, y0, x1, y1) = page.mediabox
        bbox = '%.3f,%.3f,%.3f,%.3f' % (x0, y0, x1, y1)
        self.outfp.write('<page id="%s" bbox="%s" rotate="%d">' %
                         (self.pageno, bbox, page.rotate))
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


##  PDFPageAggregator
##
class PDFPageAggregator(PDFTextDevice):

    def __init__(self, rsrc, pageno=1, laparams=None):
        PDFTextDevice.__init__(self, rsrc)
        self.laparams = laparams
        self.pageno = pageno
        self.stack = []
        return

    def begin_page(self, page, ctm):
        (x0,y0,x1,y1) = page.mediabox
        (x0,y0) = apply_matrix_pt(ctm, (x0,y0))
        (x1,y1) = apply_matrix_pt(ctm, (x1,y1))
        mediabox = (0, 0, abs(x0-x1), abs(y0-y1))
        self.cur_item = LTPage(self.pageno, mediabox)
        return

    def end_page(self, _):
        assert not self.stack
        assert isinstance(self.cur_item, LTPage)
        self.cur_item.fixate()
        if self.laparams:
            self.cur_item.analyze_layout(self.laparams)
        self.pageno += 1
        return self.cur_item

    def begin_figure(self, name, bbox, matrix):
        self.stack.append(self.cur_item)
        self.cur_item = LTFigure(name, bbox, mult_matrix(matrix, self.ctm))
        return

    def end_figure(self, _):
        fig = self.cur_item
        self.cur_item.fixate()
        self.cur_item = self.stack.pop()
        self.cur_item.add(fig)
        return

    def paint_path(self, gstate, stroke, fill, evenodd, path):
        shape = ''.join(x[0] for x in path)
        if shape == 'ml':
            # horizontal/vertical line
            (_,x0,y0) = path[0]
            (_,x1,y1) = path[1]
            (x0,y0) = apply_matrix_pt(self.ctm, (x0,y0))
            (x1,y1) = apply_matrix_pt(self.ctm, (x1,y1))
            self.cur_item.add(LTLine(gstate.linewidth, (x0,y0), (x1,y1)))
        elif shape == 'mlllh':
            # rectangle
            (_,x0,y0) = path[0]
            (_,x1,y1) = path[1]
            (_,x2,y2) = path[2]
            (_,x3,y3) = path[3]
            (x0,y0) = apply_matrix_pt(self.ctm, (x0,y0))
            (x1,y1) = apply_matrix_pt(self.ctm, (x1,y1))
            (x2,y2) = apply_matrix_pt(self.ctm, (x2,y2))
            (x3,y3) = apply_matrix_pt(self.ctm, (x3,y3))
            if ((x0 == x1 and y1 == y2 and x2 == x3 and y3 == y0) or
                (y0 == y1 and x1 == x2 and y2 == y3 and x3 == x0)):
                self.cur_item.add(LTRect(gstate.linewidth, (x0,y0,x2,y2)))
        else:
            # other polygon
            pts = []
            for p in path:
                for i in xrange(1, len(p), 2):
                    pts.append(apply_matrix_pt(self.ctm, (p[i], p[i+1])))
            self.cur_item.add(LTPolygon(gstate.linewidth, pts))
        return

    def render_chars(self, matrix, font, fontsize, charspace, scaling, chars):
        if not chars: return (0, 0)
        item = LTTextItem(matrix, font, fontsize, charspace, scaling, chars)
        self.cur_item.add(item)
        return item.adv


##  PDFConverter
##
class PDFConverter(PDFPageAggregator):

    def __init__(self, rsrc, outfp, codec='utf-8', pageno=1, laparams=None):
        PDFPageAggregator.__init__(self, rsrc, pageno=pageno, laparams=laparams)
        self.outfp = outfp
        self.codec = codec
        return

    def write(self, text):
        self.outfp.write(enc(text, self.codec))
        return


##  XMLConverter
##
class XMLConverter(PDFConverter):

    def __init__(self, rsrc, outfp, codec='utf-8', pageno=1, laparams=None):
        PDFConverter.__init__(self, rsrc, outfp, codec=codec, pageno=pageno, laparams=laparams)
        self.outfp.write('<?xml version="1.0" encoding="%s" ?>\n' % codec)
        self.outfp.write('<pages>\n')
        return
    
    def end_page(self, page):
        def render(item):
            if isinstance(item, LTPage):
                self.outfp.write('<page id="%s" bbox="%s" rotate="%d">\n' %
                                 (item.id, item.get_bbox(), item.rotate))
                for child in item:
                    render(child)
                self.outfp.write('</page>\n')
            elif isinstance(item, LTLine) and item.direction:
                self.outfp.write('<line linewidth="%d" direction="%s" bbox="%s" />' % (item.linewidth, item.direction, item.get_bbox()))
            elif isinstance(item, LTRect):
                self.outfp.write('<rect linewidth="%d" bbox="%s" />' % (item.linewidth, item.get_bbox()))
            elif isinstance(item, LTPolygon):
                self.outfp.write('<polygon linewidth="%d" bbox="%s" pts="%s"/>' % (item.linewidth, item.get_bbox(), item.get_pts()))
            elif isinstance(item, LTFigure):
                self.outfp.write('<figure id="%s" bbox="%s">\n' % (item.id, item.get_bbox()))
                for child in item:
                    render(child)
                self.outfp.write('</figure>\n')
            elif isinstance(item, LTTextLine):
                self.outfp.write('<textline bbox="%s">\n' % (item.get_bbox()))
                for child in item:
                    render(child)
                self.outfp.write('</textline>\n')
            elif isinstance(item, LTTextBox):
                self.outfp.write('<textbox id="%s" bbox="%s">\n' % (item.id, item.get_bbox()))
                for child in item:
                    render(child)
                self.outfp.write('</textbox>\n')
            elif isinstance(item, LTTextItem):
                self.outfp.write('<text font="%s" vertical="%s" bbox="%s" fontsize="%.3f">' %
                                 (enc(item.font.fontname), item.is_vertical(),
                                  item.get_bbox(), item.fontsize))
                self.write(item.text)
                self.outfp.write('</text>\n')
            elif isinstance(item, LTText):
                self.outfp.write('<text>%s</text>\n' % item.text)
            else:
                assert 0, item
            return
        page = PDFConverter.end_page(self, page)
        render(page)
        return

    def close(self):
        self.outfp.write('</pages>\n')
        return


##  HTMLConverter
##
class HTMLConverter(PDFConverter):

    def __init__(self, rsrc, outfp, codec='utf-8', pageno=1, laparams=None,
                 scale=1, showpageno=True, pagepad=50):
        PDFConverter.__init__(self, rsrc, outfp, codec=codec, pageno=pageno, laparams=laparams)
        self.showpageno = showpageno
        self.pagepad = pagepad
        self.scale = scale
        self.outfp.write('<html><head>\n')
        self.outfp.write('<meta http-equiv="Content-Type" content="text/html; charset=%s">\n' %
                         self.codec)
        self.outfp.write('</head><body>\n')
        self.yoffset = self.pagepad
        return

    def write_rect(self, color, width, x, y, w, h):
        self.outfp.write('<span style="position:absolute; border: %s %dpx solid; '
                         'left:%dpx; top:%dpx; width:%dpx; height:%dpx;"></span>\n' %
                         (color, width, x*self.scale, y*self.scale, w*self.scale, h*self.scale))
        return

    def end_page(self, page):
        def render(item):
            if isinstance(item, LTPage):
                self.yoffset += item.y1
                self.write_rect('gray', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
                if self.showpageno:
                    self.outfp.write('<div style="position:absolute; top:%dpx;">' %
                                     ((self.yoffset-item.y1)*self.scale))
                    self.outfp.write('<a name="%s">Page %s</a></div>\n' % (page.id, page.id))
                for child in item:
                    render(child)
            elif isinstance(item, LTTextItem):
                if item.vertical:
                    wmode = 'tb-rl'
                else:
                    wmode = 'lr-tb'
                self.outfp.write('<span style="position:absolute; writing-mode:%s;'
                                 ' left:%dpx; top:%dpx; font-size:%dpx;">' %
                                 (wmode, item.x0*self.scale, (self.yoffset-item.y1)*self.scale,
                                  item.fontsize*self.scale))
                self.write(item.text)
                self.outfp.write('</span>\n')
                if self.debug:
                    self.write_rect('red', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
            elif isinstance(item, LTPolygon):
                self.write_rect('black', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
            elif isinstance(item, LTTextLine):
                for child in item:
                    render(child)
            elif isinstance(item, LTTextBox):
                self.write_rect('blue', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
                for child in item:
                    render(child)
            elif isinstance(item, LTFigure):
                self.write_rect('green', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
                for child in item:
                    render(child)
            return
        page = PDFConverter.end_page(self, page)
        render(page)
        self.yoffset += self.pagepad
        return

    def close(self):
        self.outfp.write('<div style="position:absolute; top:0px;">Page: %s</div>\n' %
                         ', '.join('<a href="#%s">%s</a>' % (i,i) for i in xrange(1,self.pageno)))
        self.outfp.write('</body></html>\n')
        return


##  TextConverter
##
class TextConverter(PDFConverter):

    def __init__(self, rsrc, outfp, codec='utf-8', pageno=1, laparams=None,
                 showpageno=False):
        PDFConverter.__init__(self, rsrc, outfp, codec=codec, pageno=pageno, laparams=laparams)
        self.showpageno = showpageno
        return

    def write(self, text):
        self.outfp.write(text.encode(self.codec, 'ignore'))
        return

    def end_page(self, page):
        def render(item):
            if isinstance(item, LTText):
                self.write(item.text)
            elif isinstance(item, LayoutContainer):
                for child in item:
                    render(child)
            if isinstance(item, LTTextBox):
                self.write('\n')
        page = PDFConverter.end_page(self, page)
        if self.showpageno:
            self.write('Page %d\n' % page.id)
        render(page)
        self.write('\f')
        return
