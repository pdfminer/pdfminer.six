#!/usr/bin/env python
from pdfdevice import PDFDevice
from pdffont import PDFUnicodeNotDefined
from layout import LayoutContainer, LTPage, LTText, LTLine, LTRect, LTFigure, LTTextBox
from utils import mult_matrix, translate_matrix, enc


##  PDFPageAggregator
##
class PDFPageAggregator(PDFDevice):

  def __init__(self, rsrc, pageno=1, cluster_margin=None):
    PDFDevice.__init__(self, rsrc)
    self.cluster_margin = cluster_margin
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
    if self.cluster_margin:
      self.cur_item.group_text(self.cluster_margin)
    return self.cur_item

  def begin_figure(self, name, bbox):
    self.stack.append(self.cur_item)
    self.cur_item = LTFigure(name, bbox)
    return
  
  def end_figure(self, _):
    fig = self.cur_item
    self.cur_item.fixate()
    self.cur_item = self.stack.pop()
    self.cur_item.add(fig)
    return

  def handle_undefined_char(self, cidcoding, cid):
    if self.debug:
      print >>stderr, 'undefined: %r, %r' % (cidcoding, cid)
    return self.undefined_char

  def paint_path(self, gstate, matrix, stroke, fill, evenodd, path):
    shape = ''.join(x[0] for x in path)
    if shape == 'ml': # horizontal/vertical line
      (_,x0,y0) = path[0]
      (_,x1,y1) = path[1]
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
    chars = []
    for x in seq:
      if isinstance(x, int) or isinstance(x, float):
        (dx,dy) = self.render_chars(textmatrix, textstate, chars)
        dx -= x * textstate.scaling * .0001
        textmatrix = translate_matrix(textmatrix, (dx, dy))
        chars = []
      else:
        for cid in font.decode(x):
          try:
            char = font.to_unicode(cid)
          except PDFUnicodeNotDefined, e:
            (cidcoding, cid) = e.args
            char = self.handle_undefined_char(cidcoding, cid)
          chars.append((char, cid))
          if textstate.wordspace and not font.is_multibyte() and cid == 32:
            (dx,dy) = self.render_chars(textmatrix, textstate, chars)
            dx += textstate.wordspace * textstate.scaling * .01
            textmatrix = translate_matrix(textmatrix, (dx, dy))
            chars = []
    self.render_chars(textmatrix, textstate, chars)
    return


##  PDFConverter
##
class PDFConverter(PDFPageAggregator):
  
  def __init__(self, rsrc, outfp, pageno=1, cluster_margin=None, codec='utf-8'):
    PDFPageAggregator.__init__(self, rsrc, pageno=pageno, cluster_margin=cluster_margin)
    self.outfp = outfp
    self.codec = codec
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
  
  def render_image(self, stream, size, matrix):
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
    self.write(text)
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
      elif isinstance(item, LTLine):
        self.outfp.write('<line linewidth="%d" direction="%s" bbox="%s" />' % (item.linewidth, item.direction, item.get_bbox()))
      elif isinstance(item, LTRect):
        self.outfp.write('<rect linewidth="%d" bbox="%s" />' % (item.linewidth, item.get_bbox()))
      elif isinstance(item, LTFigure):
        self.outfp.write('<figure id="%s" bbox="%s">\n' % (item.id, item.get_bbox()))
        for child in item:
          render(child)
        self.outfp.write('</figure>\n')
      elif isinstance(item, LTTextBox):
        self.outfp.write('<textbox id="%s" bbox="%s">\n' % (item.id, item.get_bbox()))
        for child in item:
          render(child)
        self.outfp.write('</textbox>\n')
      return
    page = PDFConverter.end_page(self, page)
    render(page)
    return


##  HTMLConverter
##
class HTMLConverter(PDFConverter):

  def __init__(self, rsrc, outfp, pageno=1, cluster_margin=None, codec='utf-8',
               scale=1, showpageno=True, pagepad=50):
    PDFConverter.__init__(self, rsrc, outfp, pageno=pageno, cluster_margin=cluster_margin, codec=codec)
    self.showpageno = showpageno
    self.pagepad = pagepad
    self.scale = scale
    self.outfp.write('<html><head>\n')
    self.outfp.write('<meta http-equiv="Content-Type" content="text/html; charset=%s">\n' %
                     self.codec)
    self.outfp.write('</head><body>\n')
    self.yoffset = self.pagepad
    self.show_text_border = False
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
        if self.show_text_border:
          self.write_rect('red', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
      elif isinstance(item, LTLine) or isinstance(item, LTRect):
        self.write_rect('black', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
      elif isinstance(item, LayoutContainer):
        self.write_rect('blue', 1, item.x0, self.yoffset-item.y1, item.width, item.height)
        for child in item:
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

  def __init__(self, rsrc, outfp, pageno=1, cluster_margin=None, codec='utf-8',
               showpageno=False, word_margin=0.2):
    if cluster_margin == None:
      cluster_margin = 0.5
    PDFConverter.__init__(self, rsrc, outfp, pageno=pageno, cluster_margin=cluster_margin, codec=codec)
    self.showpageno = showpageno
    self.word_margin = word_margin
    return
  
  def end_page(self, page):
    def render(item):
      if isinstance(item, LTText):
        self.outfp.write(obj.text.encode(self.codec, 'replace'))
        self.outfp.write('\n')
      elif isinstance(item, LTTextBox):
        for line in item.get_lines(self.word_margin):
          self.outfp.write(line.encode(self.codec, 'replace')+'\n')
        self.outfp.write('\n')
      elif isinstance(item, LayoutContainer):
        for child in item:
          render(child)
    page = PDFConverter.end_page(self, page)
    if self.showpageno:
      self.outfp.write('Page %d\n' % page.id)
    render(page)
    self.outfp.write('\f')
    return
