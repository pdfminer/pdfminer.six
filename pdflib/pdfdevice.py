#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdffont import PDFUnicodeNotDefined
from utils import mult_matrix, apply_matrix, apply_matrix_norm, translate_matrix


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
    self.origin = (tx,ty)
    self.direction = 0
    self.text = ''
    scaling *= .01
    size = (font.get_ascent() - font.get_descent()) * fontsize
    if not self.font.is_vertical():
      # horizontal text
      spwidth = font.space_width()
      self.direction = 1
      w = 0
      dx = 0
      prev = ' '
      for (char,cid,t) in chars:
        if char:
          if prev != ' ' and spwidth < dx:
            self.text += ' '
          prev = char
          self.text += char
          dx = 0
          w += (font.char_width(cid) * fontsize + charspace) * scaling
        else:
          t *= .001
          dx -= t
          w -= t * fontsize * scaling
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
      for (char,cid,disp) in chars:
        if not char: continue
        (_,disp) = apply_matrix_norm(self.matrix, (0, (1000-disp)*fontsize*.001))
        self.text += font.to_unicode(cid)
        h += (font.char_width(cid) * fontsize + charspace) * scaling
        break
      for (char,cid,_) in chars[1:]:
        if not char: continue
        self.text += font.to_unicode(cid)
        h += (font.char_width(cid) * fontsize + charspace) * scaling
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

  def __init__(self, rsrc, pageno=1, splitwords=False):
    PDFDevice.__init__(self, rsrc)
    self.pageno = pageno
    self.splitwords = splitwords
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

  def render_string(self, textstate, textmatrix, seq):
    font = textstate.font
    chars = []
    for x in seq:
      if isinstance(x, int) or isinstance(x, float):
        chars.append((None, None, x))
      else:
        for cid in font.decode(x):
          try:
            char = font.to_unicode(cid)
          except PDFUnicodeNotDefined, e:
            (cidcoding, cid) = e.args
            char = self.handle_undefined_char(cidcoding, cid)
          chars.append((char, cid, font.char_disp(cid)))
    textmatrix = mult_matrix(textmatrix, self.ctm)
    word = []
    for (char, cid, disp) in chars:
      word.append((char,cid,disp))
      if self.splitwords and cid == 32 and not font.is_multibyte():
        if word:
          item = TextItem(textmatrix, font, textstate.fontsize, textstate.charspace, textstate.scaling, word)
          self.cur_item.add(item)
          (dx,dy) = item.adv
          dx += textstate.wordspace * textstate.scaling * .01
          textmatrix = translate_matrix(textmatrix, (dx, dy))
          word = []
    if word:
      item = TextItem(textmatrix, font, textstate.fontsize, textstate.charspace, textstate.scaling, word)
      self.cur_item.add(item)
    return
