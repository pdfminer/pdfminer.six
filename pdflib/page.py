#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdfinterp import PDFDevice, PDFUnicodeNotDefined, \
     mult_matrix, apply_matrix


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
  
  def __init__(self, matrix, font, fontsize, width, text):
    self.matrix = matrix
    self.font = font
    (a,b,c,d,tx,ty) = self.matrix
    self.origin = (tx,ty)
    self.direction = 0
    if not self.font.is_vertical():
      self.direction = 1
      (self.width, self.height) = apply_matrix((a,b,c,d,0,0), (width,fontsize))
      self.width = abs(self.width)
      (_,ascent) = apply_matrix((a,b,c,d,0,0), (0,font.ascent*fontsize*0.001))
      (_,descent) = apply_matrix((a,b,c,d,0,0), (0,font.descent*fontsize*0.001))
      ty += descent
      self.bbox = (tx, ty, tx+self.width, ty+self.height)
    else:
      self.direction = 2
      (self.width, self.height) = apply_matrix((a,b,c,d,0,0), (fontsize,width))
      self.width = abs(self.width)
      (disp,_) = text[0]
      (_,disp) = apply_matrix((a,b,c,d,0,0), (0, (1000-disp)*fontsize*0.001))
      tx -= self.width/2
      ty += disp
      self.bbox = (tx, ty+self.height, tx+self.width, ty)
    self.text = ''.join( c for (_,c) in text )
    (w,h) = apply_matrix((a,b,c,d,0,0), (fontsize,fontsize))
    self.fontsize = max(w,h)
    return
  
  def __repr__(self):
    return ('<text matrix=%r font=%r fontsize=%r width=%r height=%r text=%r>' %
            (self.matrix, self.font, self.fontsize, self.width, self.height, self.text))


##  TextConverter
##
class TextConverter(PDFDevice):

  def __init__(self, rsrc, outfp, codec='utf-8', debug=0):
    PDFDevice.__init__(self, rsrc, debug=debug)
    self.outfp = outfp
    self.codec = codec
    self.pageno = 0
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

  def render_string(self, textstate, textmatrix, size, seq, ratio=0.6):
    font = textstate.font
    spwidth = int(-font.char_width(32) * ratio) # space width
    text = []
    for x in seq:
      if isinstance(x, int) or isinstance(x, float):
        if not font.is_vertical() and x <= spwidth:
          text.append((0, ' '))
      else:
        chars = font.decode(x)
        for cid in chars:
          try:
            char = font.to_unicode(cid)
            text.append((font.char_disp(cid), char))
          except PDFUnicodeNotDefined, e:
            (cidcoding, cid) = e.args
            s = self.handle_undefined_char(cidcoding, cid)
            if s:
              text.append(s)
    if text:
      item = TextItem(mult_matrix(textmatrix, self.ctm),
                      font, textstate.fontsize, size, text)
      self.cur_item.add(item)
    return
