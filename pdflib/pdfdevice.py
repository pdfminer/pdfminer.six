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

  def paint_path(self, graphicstate, matrix, stroke, fill, evenodd, path):
    return
  def render_string(self, textstate, textmatrix, seq):
    return
  def render_image(self, stream, size, matrix):
    return


##  Page
##
class PageItem(object):

  def __init__(self, (x0,y0,x1,y1)):
    #assert x0 <= x1 and y0 <= y1
    self.x0 = x0
    self.y0 = y0
    self.x1 = x1
    self.y1 = y1
    self.width = x1-x0
    self.height = y1-y0
    return

  def __repr__(self):
    return ('<pageitem bbox=%s>' % (self.bbox()))
  
  def bbox(self):
    return rect2str((self.x0, self.y0, self.x1, self.y1))
  
  def hoverlap(self, obj):
    assert isinstance(obj, PageItem)
    if self.x1 <= obj.x0 or obj.x1 <= self.x0:
      return 0
    else:
      return min(abs(self.x0-obj.x1), abs(self.x1-obj.x0))

  def voverlap(self, obj):
    assert isinstance(obj, PageItem)
    if self.y1 <= obj.y0 or obj.y1 <= self.y0:
      return 0
    else:
      return min(abs(self.y0-obj.y1), abs(self.y1-obj.y0))
  
  
class PageContainer(PageItem):
  
  def __init__(self, bbox):
    PageItem.__init__(self, bbox)
    self.objs = []
    return
  
  def add(self, obj):
    self.objs.append(obj)
    return
  
class Page(PageContainer):
  
  def __init__(self, id, bbox, rotate=0):
    PageContainer.__init__(self, bbox)
    self.id = id
    self.rotate = rotate
    return
  
  def __repr__(self):
    return ('<page id=%r bbox=%s rotate=%r>' % (self.id, self.bbox(), self.rotate))


##  FigureItem
##
class FigureItem(PageContainer):
  
  def __init__(self, id, bbox):
    PageContainer.__init__(self, bbox)
    self.id = id
    return
  
  def __repr__(self):
    return ('<figure id=%r bbox=%s>' % (self.id, self.bbox()))
  

##  TextItem
##
class TextItem(PageItem):
  
  def __init__(self, matrix, font, fontsize, charspace, scaling, chars):
    assert chars
    self.matrix = matrix
    self.font = font
    (_,_,_,_,tx,ty) = self.matrix
    self.vertical = self.font.is_vertical()
    self.text = ''.join( char for (char,_) in chars )
    adv = sum( font.char_width(cid) for (_,cid) in chars )
    adv = (adv * fontsize + len(chars)*charspace) * scaling * .01
    size = (font.get_ascent() - font.get_descent()) * fontsize
    if not self.vertical:
      # horizontal text
      self.vertical = False
      (dx,dy) = apply_matrix_norm(self.matrix, (adv,size))
      (_,descent) = apply_matrix_norm(self.matrix, (0,font.get_descent() * fontsize))
      ty += descent
      self.adv = (dx, 0)
      bbox = (tx, ty, tx+dx, ty+dy)
    else:
      # vertical text
      (_,cid) = chars[0]
      (_,disp) = apply_matrix_norm(self.matrix, (0, (1000-font.char_disp(cid))*fontsize*.001))
      (dx,dy) = apply_matrix_norm(self.matrix, (size,adv))
      tx -= dx/2
      ty += disp
      self.adv = (0, dy)
      bbox = (tx, ty+dy, tx+dx, ty)
    self.fontsize = max(apply_matrix_norm(self.matrix, (size,size)))
    PageItem.__init__(self, bbox)
    return

  def __len__(self):
    return len(self.text)
  
  def __repr__(self):
    return ('<text matrix=%s font=%r fontsize=%.1f bbox=%s adv=%s text=%r>' %
            (matrix2str(self.matrix), self.font, self.fontsize, self.bbox(),
             point2str(self.adv), self.text))


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
