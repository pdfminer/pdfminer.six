#!/usr/bin/env python
import sys
from pdfminer.pdfdevice import PDFDevice
from pdfminer.pdffont import PDFUnicodeNotDefined
from pdfminer.layout import LayoutContainer, LTPage, LTText, LTLine, LTRect, LTFigure, LTTextBox, LTAnon
from pdfminer.utils import mult_matrix, translate_matrix, apply_matrix_pt, enc


##  PDFPageAggregator
##
class PDFPageAggregator(PDFDevice):

  def __init__(self, rsrc, pageno=1, char_margin=None, line_margin=None):
    PDFDevice.__init__(self, rsrc)
    self.char_margin = char_margin
    self.line_margin = line_margin
    self.undefined_char = '?'
    self.pageno = pageno
    self.stack = []
    return

  def begin_page(self, page):
    self.cur_item = LTPage(self.pageno, page.mediabox, page.rotate)
    return
  
  def end_page(self, _):
    assert not self.stack
    assert isinstance(self.cur_item, LTPage)
    self.cur_item.fixate()
    self.pageno += 1
    if self.char_margin != None and self.line_margin != None:
      self.cur_item.group_text(self.char_margin, self.line_margin)
    return self.cur_item

  def begin_figure(self, name, bbox, matrix):
    self.stack.append(self.cur_item)
    self.cur_item = LTFigure(name, bbox, matrix)
    return
  
  def end_figure(self, _):
    fig = self.cur_item
    self.cur_item.fixate()
    self.cur_item = self.stack.pop()
    self.cur_item.add(fig)
    return

  def handle_undefined_char(self, cidcoding, cid):
    if self.debug:
      print >>sys.stderr, 'undefined: %r, %r' % (cidcoding, cid)
    return self.undefined_char

  def paint_path(self, gstate, stroke, fill, evenodd, path):
    shape = ''.join(x[0] for x in path)
    if shape == 'ml': # horizontal/vertical line
      (_,x0,y0) = path[0]
      (_,x1,y1) = path[1]
      (x0,y0) = apply_matrix_pt(self.ctm, (x0,y0))
      (x1,y1) = apply_matrix_pt(self.ctm, (x1,y1))
      if y0 == y1:
        # horizontal ruler
        self.cur_item.add(LTLine(gstate.linewidth, 'H', (x0,y0,x1,y1)))
      elif x0 == x1:
        # vertical ruler
        self.cur_item.add(LTLine(gstate.linewidth, 'V', (x0,y0,x1,y1)))
    elif shape == 'mlllh':
      # rectangle
      (_,x0,y0) = path[0]
      (_,x1,y1) = path[1]
      (_,x2,y2) = path[2]
      (_,x3,y3) = path[3]
      (x0,y0) = apply_matrix_pt(self.ctm, (x0,y0))
      (x1,y1) = apply_matrix_pt(self.ctm, (x1,y1))
      (x2,y2) = apply_matrix_pt(self.ctm, (x2,y2))
      (x3,y3) = apply_matrix_pt(self.ctm, (x3,y2))
      if ((x0 == x1 and y1 == y2 and x2 == x3 and y3 == y0) or
          (y0 == y1 and x1 == x2 and y2 == y3 and x3 == x0)):
        self.cur_item.add(LTRect(gstate.linewidth, (x0,y0,x2,y2)))
    return
  
  def render_chars(self, textmatrix, textstate, chars):
    if not chars: return (0, 0)
    item = LTText(textmatrix, textstate.font, textstate.fontsize,
                  textstate.charspace, textstate.scaling, chars)
    self.cur_item.add(item)
    return item.adv

  def render_string(self, textstate, textmatrix, seq):
    font = textstate.font
    textmatrix = mult_matrix(textmatrix, self.ctm)
    scaling = textstate.scaling * .01
    dxscale = scaling / (font.hscale*1000) * .01
    wordspace = textstate.wordspace * scaling
    chars = []
    for x in seq:
      if isinstance(x, int) or isinstance(x, float):
        (dx,dy) = self.render_chars(textmatrix, textstate, chars)
        textmatrix = translate_matrix(textmatrix, (dx-x*dxscale, dy))
        chars = []
      else:
        for cid in font.decode(x):
          try:
            char = font.to_unicode(cid)
          except PDFUnicodeNotDefined, e:
            (cidcoding, cid) = e.args
            char = self.handle_undefined_char(cidcoding, cid)
          chars.append((char, cid))
          if cid == 32 and textstate.wordspace and not font.is_multibyte():
            (dx,dy) = self.render_chars(textmatrix, textstate, chars)
            textmatrix = translate_matrix(textmatrix, (dx+wordspace, dy))
            chars = []
    self.render_chars(textmatrix, textstate, chars)
    return


##  PDFConverter
##
class PDFConverter(PDFPageAggregator):
  
  def __init__(self, rsrc, outfp, codec='utf-8', pageno=1,
               char_margin=None, line_margin=None, word_margin=None):
    PDFPageAggregator.__init__(self, rsrc, pageno=pageno,
                               char_margin=char_margin, line_margin=line_margin)
    self.outfp = outfp
    self.codec = codec
    self.word_margin = word_margin
    return

  def write(self, text):
    self.outfp.write(enc(text, self.codec))
    return
  
  
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
  
  def render_string(self, textstate, textmatrix, seq):
    font = textstate.font
    text = ''
    for x in seq:
      if not isinstance(x, str): continue
      chars = font.decode(x)
      for cid in chars:
        try:
          char = font.to_unicode(cid)
          text += char
        except PDFUnicodeNotDefined:
          pass
    self.outfp.write(enc(text, self.codec))
    return

  def begin_page(self, page):
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


##  SGMLConverter
##
class SGMLConverter(PDFConverter):

  def end_page(self, page):
    def render(item):
      if isinstance(item, LTPage):
        self.outfp.write('<page id="%s" bbox="%s" rotate="%d">\n' %
                         (item.id, item.get_bbox(), item.rotate))
        for child in item:
          render(child)
        self.outfp.write('</page>\n')
      elif isinstance(item, LTText):
        self.outfp.write('<text font="%s" vertical="%s" bbox="%s" fontsize="%.3f">' %
                         (enc(item.font.fontname), item.is_vertical(),
                          item.get_bbox(), item.fontsize))
        self.write(item.text)
        self.outfp.write('</text>\n')
      elif isinstance(item, LTAnon):
        if item.text == ' ':
          self.outfp.write('<space>\n')
        elif item.text == '\n':
          self.outfp.write('<newline>\n')
      elif isinstance(item, LTLine):
        self.outfp.write('<line linewidth="%d" direction="%s" bbox="%s" />' % (item.linewidth, item.direction, item.get_bbox()))
      elif isinstance(item, LTRect):
        self.outfp.write('<rect linewidth="%d" bbox="%s" />' % (item.linewidth, item.get_bbox()))
      elif isinstance(item, LTFigure):
        self.outfp.write('<figure id="%s">\n' % (item.id))
        for child in item:
          render(child)
        self.outfp.write('</figure>\n')
      elif isinstance(item, LTTextBox):
        self.outfp.write('<textbox id="%s" bbox="%s">\n' % (item.id, item.get_bbox()))
        for child in item.get_lines(self.word_margin):
          render(child)
        self.outfp.write('</textbox>\n')
      return
    page = PDFConverter.end_page(self, page)
    render(page)
    return


##  HTMLConverter
##
class HTMLConverter(PDFConverter):

  def __init__(self, rsrc, outfp, codec='utf-8', pageno=1,
               char_margin=None, line_margin=None, word_margin=None, 
               scale=1, showpageno=True, pagepad=50):
    PDFConverter.__init__(self, rsrc, outfp, codec=codec, pageno=pageno,
                          char_margin=char_margin, line_margin=line_margin, word_margin=word_margin)
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
        self.write_rect('gray', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
        if self.showpageno:
          self.outfp.write('<div style="position:absolute; top:%dpx;">' %
                           ((self.yoffset-page.y1)*self.scale))
          self.outfp.write('<a name="%s">Page %s</a></div>\n' % (page.id, page.id))
        for child in item:
          render(child)
      elif isinstance(item, LTText):
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
      elif isinstance(item, LTAnon):
        pass
      elif isinstance(item, LTLine) or isinstance(item, LTRect):
        self.write_rect('black', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
      elif isinstance(item, LTTextBox):
        self.write_rect('blue', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
        for child in item.get_lines(self.word_margin):
          render(child)
      return
    page = PDFConverter.end_page(self, page)
    self.yoffset += page.y1
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

  def __init__(self, rsrc, outfp, codec='utf-8', pageno=1,
               char_margin=None, line_margin=None, word_margin=None, 
               showpageno=False):
    PDFConverter.__init__(self, rsrc, outfp, codec=codec, pageno=pageno,
                          char_margin=char_margin, line_margin=line_margin, word_margin=word_margin)
    self.showpageno = showpageno
    return
  
  def write(self, text):
    self.outfp.write(text.encode(self.codec, 'ignore'))
    return
  
  def end_page(self, page):
    def render(item):
      if isinstance(item, LTText):
        self.write(item.text+'\n')
      elif isinstance(item, LTTextBox):
        for obj in item.get_lines(self.word_margin):
          self.write(obj.text)
        self.write('\n')
      elif isinstance(item, LayoutContainer):
        for child in item:
          render(child)
    page = PDFConverter.end_page(self, page)
    if self.showpageno:
      self.write('Page %d\n' % page.id)
    render(page)
    self.write('\f')
    return
