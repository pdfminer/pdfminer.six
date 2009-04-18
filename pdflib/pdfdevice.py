#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdffont import PDFUnicodeNotDefined
from utils import mult_matrix, apply_matrix, apply_matrix_norm, translate_matrix, \
     matrix2str, rect2str, point2str


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
  
  def render_string(self, textstate, textmatrix, seq):
    raise NotImplementedError
  def render_image(self, stream, size, matrix):
    raise NotImplementedError


##  PageItem
##
class PageItem(object):
  
  def __init__(self, id, (x0,y0,x1,y1), rotate=0):
    self.id = id
    self.bbox = (x0, y0, x1, y1)
    self.rotate = rotate
    self.objs = []
    return
  
  def __repr__(self):
    return ('<page id=%r bbox=%r rotate=%r>' % (self.id, self.bbox, self.rotate))
  
  def add(self, obj):
    self.objs.append(obj)
    return


##  FigureItem
##
class FigureItem(PageItem):
  
  def __repr__(self):
    return ('<figure id=%r bbox=%r>' % (self.id, self.bbox))
  

##  TextItem
##
class TextItem(object):
  
  def __init__(self, matrix, font, fontsize, charspace, scaling, chars):
    self.matrix = matrix
    self.font = font
    (_,_,_,_,tx,ty) = self.matrix
    self.direction = 0
    self.text = ''
    adv = 0
    for (char,cid) in chars:
      self.text += char
      adv += font.char_width(cid)
    adv = (adv * fontsize + len(chars)*charspace) * scaling * .01
    size = (font.get_ascent() - font.get_descent()) * fontsize
    if not self.font.is_vertical():
      # horizontal text
      self.direction = 1
      (dx,dy) = apply_matrix_norm(self.matrix, (adv,size))
      (_,descent) = apply_matrix_norm(self.matrix, (0,font.get_descent() * fontsize))
      ty += descent
      self.adv = (dx, 0)
      self.bbox = (tx, ty, tx+dx, ty+dy)
    else:
      # vertical text
      self.direction = 2
      (_,cid) = chars[0]
      (_,disp) = apply_matrix_norm(self.matrix, (0, (1000-font.char_disp(cid))*fontsize*.001))
      (dx,dy) = apply_matrix_norm(self.matrix, (size,adv))
      tx -= dx/2
      ty += disp
      self.adv = (0, dy)
      self.bbox = (tx, ty+dy, tx+dx, ty)
    self.fontsize = max(apply_matrix_norm(self.matrix, (size,size)))
    return
  
  def __repr__(self):
    return ('<text matrix=%s font=%r fontsize=%.1f bbox=%s text=%r adv=%s>' %
            (matrix2str(self.matrix), self.font, self.fontsize,
             rect2str(self.bbox), self.text, point2str(self.adv)))


##  PDFPageAggregator
##
class PDFPageAggregator(PDFDevice):

  def __init__(self, rsrc, pageno=1):
    PDFDevice.__init__(self, rsrc)
    self.pageno = pageno
    self.stack = []
    return

  def begin_page(self, page):
    self.cur_item = PageItem(self.pageno, page.mediabox, page.rotate)
    return
  
  def end_page(self, _):
    assert not self.stack
    assert isinstance(self.cur_item, PageItem)
    self.pageno += 1
    return self.cur_item

  def begin_figure(self, name, bbox):
    self.stack.append(self.cur_item)
    self.cur_item = FigureItem(name, bbox)
    return
  
  def end_figure(self, _):
    fig = self.cur_item
    self.cur_item = self.stack.pop()
    self.cur_item.add(fig)
    return

  def render_image(self, stream, size, matrix):
    return

  def handle_undefined_char(self, cidcoding, cid):
    if self.debug:
      print >>stderr, 'undefined: %r, %r' % (cidcoding, cid)
    return None

  def render_chars(self, textmatrix, textstate, chars):
    if not chars: return (0, 0)
    item = TextItem(textmatrix, textstate.font, textstate.fontsize, textstate.charspace, textstate.scaling, chars)
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
          if cid == 32 and not font.is_multibyte():
            (dx,dy) = self.render_chars(textmatrix, textstate, chars)
            dx += textstate.wordspace * textstate.scaling * .01
            textmatrix = translate_matrix(textmatrix, (dx, dy))
            chars = []
    self.render_chars(textmatrix, textstate, chars)
    return
