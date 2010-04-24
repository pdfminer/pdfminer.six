#!/usr/bin/env python
import sys, os.path
from pdfdevice import PDFDevice, PDFTextDevice
from pdffont import PDFUnicodeNotDefined
from pdftypes import LITERALS_DCT_DECODE
from pdfcolor import LITERAL_DEVICE_GRAY, LITERAL_DEVICE_RGB
from layout import LTContainer, LTPage, LTText, LTLine, LTRect, LTPolygon
from layout import LTFigure, LTImage, LTChar, LTTextLine, LTTextBox, LTTextGroup
from utils import apply_matrix_pt, mult_matrix
from utils import enc, bbox2str, create_bmp


##  PDFPageAggregator
##
class PDFPageAggregator(PDFTextDevice):

    def __init__(self, rsrcmgr, pageno=1, laparams=None):
        PDFTextDevice.__init__(self, rsrcmgr)
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
        self.cur_item.analyze(self.laparams)
        self.pageno += 1
        return self.cur_item

    def begin_figure(self, name, bbox, matrix):
        self.stack.append(self.cur_item)
        self.cur_item = LTFigure(name, bbox, mult_matrix(matrix, self.ctm))
        return

    def end_figure(self, _):
        fig = self.cur_item
        assert isinstance(self.cur_item, LTFigure)
        self.cur_item.fixate()
        self.cur_item.analyze(self.laparams)
        self.cur_item = self.stack.pop()
        self.cur_item.add(fig)
        return

    def render_image(self, name, stream):
        assert isinstance(self.cur_item, LTFigure)
        item = LTImage(name, stream,
                       (self.cur_item.x0, self.cur_item.y0,
                        self.cur_item.x1, self.cur_item.y1))
        self.cur_item.add(item)
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

    def render_char(self, matrix, font, fontsize, scaling, cid):
        item = LTChar(matrix, font, fontsize, scaling, cid)
        self.cur_item.add(item)
        return item.adv


##  PDFConverter
##
class PDFConverter(PDFPageAggregator):

    def __init__(self, rsrcmgr, outfp, codec='utf-8', pageno=1, laparams=None):
        PDFPageAggregator.__init__(self, rsrcmgr, pageno=pageno, laparams=laparams)
        self.outfp = outfp
        self.codec = codec
        return

    def write(self, text):
        self.outfp.write(enc(text, self.codec))
        return

    def write_image(self, image):
        stream = image.stream
        filters = stream.get_filters()
        if len(filters) == 1 and filters[0] in LITERALS_DCT_DECODE:
            ext = '.jpg'
            data = stream.get_rawdata()
        elif stream.colorspace is LITERAL_DEVICE_RGB:
            ext = '.bmp'
            data = create_bmp(stream.get_data(), stream.bits*3, image.width, image.height)
        elif stream.colorspace is LITERAL_DEVICE_GRAY:
            ext = '.bmp'
            data = create_bmp(stream.get_data(), stream.bits, image.width, image.height)
        else:
            ext = '.img'
            data = stream.get_data()
        name = image.name+ext
        path = os.path.join(self.outdir, name)
        fp = file(path, 'wb')
        fp.write(data)
        fp.close()
        return name
        return
    

##  TextConverter
##
class TextConverter(PDFConverter):

    def __init__(self, rsrcmgr, outfp, codec='utf-8', pageno=1, laparams=None,
                 showpageno=False):
        PDFConverter.__init__(self, rsrcmgr, outfp, codec=codec, pageno=pageno, laparams=laparams)
        self.showpageno = showpageno
        return

    def write(self, text):
        self.outfp.write(text.encode(self.codec, 'ignore'))
        return

    def end_page(self, page):
        def render(item):
            if isinstance(item, LTText):
                self.write(item.text)
            elif isinstance(item, LTContainer):
                for child in item:
                    render(child)
            if isinstance(item, LTTextBox):
                self.write('\n')
        page = PDFConverter.end_page(self, page)
        if self.showpageno:
            self.write('Page %s\n' % page.pageid)
        render(page)
        self.write('\f')
        return


##  HTMLConverter
##
class HTMLConverter(PDFConverter):

    def __init__(self, rsrcmgr, outfp, codec='utf-8', pageno=1, laparams=None,
                 scale=1, showpageno=True, pagepad=50, outdir=None):
        PDFConverter.__init__(self, rsrcmgr, outfp, codec=codec, pageno=pageno, laparams=laparams)
        self.showpageno = showpageno
        self.pagepad = pagepad
        self.outdir = outdir
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
                         (color, width,
                          x*self.scale, (self.yoffset-y)*self.scale,
                          w*self.scale, h*self.scale))
        return

    def write_text(self, text, x, y, size):
        self.outfp.write('<span style="position:absolute; left:%dpx; top:%dpx; font-size:%dpx;">' %
                         (x*self.scale, (self.yoffset-y)*self.scale, size*self.scale))
        self.write(text)
        self.outfp.write('</span>\n')
        return

    def end_page(self, page):
        def render(item):
            if isinstance(item, LTPage):
                self.yoffset += item.y1
                self.write_rect('gray', 1, item.x0, item.y1, item.width, item.height)
                if self.showpageno:
                    self.outfp.write('<div style="position:absolute; top:%dpx;">' %
                                     ((self.yoffset-item.y1)*self.scale))
                    self.outfp.write('<a name="%s">Page %s</a></div>\n' % (page.pageid, page.pageid))
                for child in item:
                    render(child)
            elif isinstance(item, LTChar):
                self.write_text(item.text, item.x0, item.y1, item.get_size())
                if self.debug:
                    self.write_rect('red', 1, item.x0, item.y1, item.width, item.height)
            elif isinstance(item, LTPolygon):
                self.write_rect('black', 1, item.x0, item.y1, item.width, item.height)
            elif isinstance(item, LTTextLine):
                for child in item:
                    render(child)
            elif isinstance(item, LTTextBox):
                self.write_rect('blue', 1, item.x0, item.y1, item.width, item.height)
                for child in item:
                    render(child)
                if self.debug:
                    self.write_text(str(item.index+1), item.x0, item.y1, 20)
            elif isinstance(item, LTFigure):
                self.write_rect('green', 1, item.x0, item.y1, item.width, item.height)
                for child in item:
                    render(child)
            elif isinstance(item, LTImage):
                if self.outdir:
                    name = self.write_image(item)
                    self.outfp.write('<img src="%s" style="position:absolute; left:%dpx; top:%dpx;" '
                                     'width="%d" height="%d" />\n' %
                                     (enc(name),
                                      item.x0*self.scale, (self.yoffset-item.y1)*self.scale,
                                      item.width*self.scale, item.height*self.scale))
            return
        page = PDFConverter.end_page(self, page)
        render(page)
        if self.debug and page.layout:
            def show_layout(item):
                if isinstance(item, LTTextGroup):
                    self.write_rect('red', 1, item.x0, item.y1, item.width, item.height)
                    for child in item:
                        show_layout(child)
                return
            show_layout(page.layout)
        self.yoffset += self.pagepad
        return

    def close(self):
        self.outfp.write('<div style="position:absolute; top:0px;">Page: %s</div>\n' %
                         ', '.join('<a href="#%s">%s</a>' % (i,i) for i in xrange(1,self.pageno)))
        self.outfp.write('</body></html>\n')
        return


##  XMLConverter
##
class XMLConverter(PDFConverter):

    def __init__(self, rsrcmgr, outfp, codec='utf-8', pageno=1, laparams=None, outdir=None):
        PDFConverter.__init__(self, rsrcmgr, outfp, codec=codec, pageno=pageno, laparams=laparams)
        self.outdir = outdir
        self.outfp.write('<?xml version="1.0" encoding="%s" ?>\n' % codec)
        self.outfp.write('<pages>\n')
        return

    def end_page(self, page):
        def render(item):
            if isinstance(item, LTPage):
                self.outfp.write('<page id="%s" bbox="%s" rotate="%d">\n' %
                                 (item.pageid, bbox2str(item.bbox), item.rotate))
                for child in item:
                    render(child)
                self.outfp.write('</page>\n')
            elif isinstance(item, LTLine):
                self.outfp.write('<line linewidth="%d" bbox="%s" />\n' %
                                 (item.linewidth, bbox2str(item.bbox)))
            elif isinstance(item, LTRect):
                self.outfp.write('<rect linewidth="%d" bbox="%s" />\n' %
                                 (item.linewidth, bbox2str(item.bbox)))
            elif isinstance(item, LTPolygon):
                self.outfp.write('<polygon linewidth="%d" bbox="%s" pts="%s"/>\n' %
                                 (item.linewidth, bbox2str(item.bbox), item.get_pts()))
            elif isinstance(item, LTFigure):
                self.outfp.write('<figure name="%s" bbox="%s">\n' %
                                 (item.name, bbox2str(item.bbox)))
                for child in item:
                    render(child)
                self.outfp.write('</figure>\n')
            elif isinstance(item, LTTextLine):
                self.outfp.write('<textline bbox="%s">\n' % bbox2str(item.bbox))
                for child in item:
                    render(child)
                self.outfp.write('</textline>\n')
            elif isinstance(item, LTTextBox):
                self.outfp.write('<textbox id="%d" bbox="%s">\n' % (item.index, bbox2str(item.bbox)))
                for child in item:
                    render(child)
                self.outfp.write('</textbox>\n')
            elif isinstance(item, LTChar):
                vertical = ''
                if item.is_vertical():
                    vertical = 'vertical="true" '
                self.outfp.write('<text font="%s" %sbbox="%s" size="%.3f">' %
                                 (enc(item.font.fontname), vertical,
                                  bbox2str(item.bbox), item.get_size()))
                self.write(item.text)
                self.outfp.write('</text>\n')
            elif isinstance(item, LTText):
                self.outfp.write('<text>%s</text>\n' % item.text)
            elif isinstance(item, LTImage):
                if self.outdir:
                    name = self.write_image(item)
                    self.outfp.write('<image src="%s" width="%d" height="%d" />\n' %
                                     (enc(name), item.width, item.height))
                else:
                    self.outfp.write('<image width="%d" height="%d" />\n' %
                                     (item.width, item.height))
            else:
                assert 0, item
            return
        page = PDFConverter.end_page(self, page)
        render(page)
        if page.layout:
            def show_layout(item):
                if isinstance(item, LTTextBox):
                    self.outfp.write('<textbox id="%d" bbox="%s" />\n' % (item.index, bbox2str(item.bbox)))
                elif isinstance(item, LTTextGroup):
                    self.outfp.write('<textgroup bbox="%s">\n' % bbox2str(item.bbox))
                    for child in item:
                        show_layout(child)
                    self.outfp.write('</textgroup>\n')
                return
            self.outfp.write('<layout>\n')
            show_layout(page.layout)
            self.outfp.write('</layout>\n')
        return

    def close(self):
        self.outfp.write('</pages>\n')
        return
