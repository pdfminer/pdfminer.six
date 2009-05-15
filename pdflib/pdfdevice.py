#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdffont import PDFUnicodeNotDefined
from page import Page, FigureItem, TextItem
from utils import mult_matrix, translate_matrix


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

  def begin_page(self, page):
    return
  def end_page(self, page):
    return
  def begin_figure(self, name, bbox):
    return
  def end_figure(self, name):
    return

  def paint_path(self, graphicstate, matrix, stroke, fill, evenodd, path):
    return
  def render_string(self, textstate, textmatrix, seq):
    return
  def render_image(self, stream, size, matrix):
    return


##  PDFPageAggregator
##
class PDFPageAggregator(PDFDevice):

  def __init__(self, rsrc, pageno=1):
    PDFDevice.__init__(self, rsrc)
    self.pageno = pageno
    self.stack = []
    return

  def begin_page(self, page):
    self.cur_item = Page(self.pageno, page.mediabox, page.rotate)
    return
  
  def end_page(self, _):
    assert not self.stack
    assert isinstance(self.cur_item, Page)
    self.cur_item.fixate()
    self.pageno += 1
    return self.cur_item

  def begin_figure(self, name, bbox):
    self.stack.append(self.cur_item)
    self.cur_item = FigureItem(name, bbox)
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
    return '?'

  def paint_path(self, graphicstate, matrix, stroke, fill, evenodd, path):
    shape = ''.join(x[0] for x in path)
    if shape == 'ml': # single line
      if path[0][1] == path[1][1]:
        #print 'vertical'
        pass
      elif path[0][2] == path[1][2]:
        #print 'horizontal'
        pass
    elif shape == 'mlllh': # rectangle
      if ((path[0][1] == path[1][1] and path[1][2] == path[2][2] and
           path[2][1] == path[3][1] and path[3][2] == path[0][2]) or
          (path[0][2] == path[1][2] and path[1][1] == path[2][1] and
           path[2][2] == path[3][2] and path[3][1] == path[0][1])):
        pass
    return
  
  def render_chars(self, textmatrix, textstate, chars):
    if not chars: return (0, 0)
    item = TextItem(textmatrix, textstate.font, textstate.fontsize,
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
