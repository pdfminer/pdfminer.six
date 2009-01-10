#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdflib.pdffont import PDFUnicodeNotDefined
from pdflib.utils import mult_matrix, apply_matrix, apply_matrix_norm, translate_matrix


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
  
  SPACE_WIDTH = 0.6
  
  def __init__(self, matrix, font, fontsize, charspace, scaling, text):
    self.matrix = matrix
    self.font = font
    (_,_,_,_,tx,ty) = self.matrix
    self.origin = (tx,ty)
    self.direction = 0
    self.text = ''
    scaling *= .01
    size = (font.get_ascent() - font.get_descent()) * fontsize
    if not self.font.is_vertical():
      # horizontal text
      spwidth = font.char_width(32) * self.SPACE_WIDTH # space width
      self.direction = 1
      w = 0
      dx = 0
      prev = ' '
      for t in text:
        if isinstance(t, tuple):
          if prev != ' ' and spwidth < dx:
            self.text += ' '
          (_,char) = t
          self.text += char
          prev = char
          dx = 0
          w += (font.char_width(ord(char)) * fontsize + charspace) * scaling
        else:
          t *= .001
          dx -= t
          w += t * fontsize * scaling
      (_,descent) = apply_matrix_norm(self.matrix, (0,font.get_descent() * fontsize))
      ty += descent
      (w,h) = apply_matrix_norm(self.matrix, (w,size))
      self.adv = (w, 0)
      self.bbox = (tx, ty, tx+w, ty+h)
    else:
      # vertical text
      self.direction = 2
      disp = 0
      h = 0
      for t in text:
        if isinstance(t, tuple):
          (disp,char) = t
          (_,disp) = apply_matrix_norm(self.matrix, (0, (1000-disp)*fontsize*.001))
          self.text += char
          h += (font.char_width(ord(char)) * fontsize + charspace) * scaling
          break
      for t in text:
        if isinstance(t, tuple):
          (_,char) = t
          self.text += char
          h += (font.char_width(ord(char)) * fontsize + charspace) * scaling
      (w,h) = apply_matrix_norm(self.matrix, (size,h))
      tx -= w/2
      ty += disp
      self.adv = (0, h)
      self.bbox = (tx, ty+h, tx+w, ty)
    self.fontsize = max(apply_matrix_norm(self.matrix, (size,size)))
    return
  
  def __repr__(self):
    return ('<text matrix=%r font=%r fontsize=%r bbox=%r text=%r adv=%r>' %
            (self.matrix, self.font, self.fontsize, self.bbox, self.text, self.adv))


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
    return

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

  def render_string(self, textstate, textmatrix, seq):
    font = textstate.font
    text = []
    textmatrix = mult_matrix(textmatrix, self.ctm)
    for x in seq:
      if isinstance(x, int) or isinstance(x, float):
        text.append(x)
      else:
        chars = font.decode(x)
        for cid in chars:
          try:
            char = font.to_unicode(cid)
            text.append((font.char_disp(cid), char))
          except PDFUnicodeNotDefined, e:
            (cidcoding, cid) = e.args
            unc = self.handle_undefined_char(cidcoding, cid)
            if unc:
              text.append(unc)
          if cid == 32 and not font.is_multibyte():
            if text:
              item = TextItem(textmatrix, font, textstate.fontsize, textstate.charspace, textstate.scaling, text)
              self.cur_item.add(item)
              (dx,dy) = item.adv
              dx += textstate.wordspace * textstate.scaling * .01
              textmatrix = translate_matrix(textmatrix, (dx, dy))
              text = []
    if text:
      item = TextItem(textmatrix, font, textstate.fontsize, textstate.charspace, textstate.scaling, text)
      self.cur_item.add(item)
    return
