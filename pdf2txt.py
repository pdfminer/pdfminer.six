#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdfparser import PDFDocument, PDFParser
from pdfinterp import PDFDevice, PDFResourceManager, \
     PDFPageInterpreter, PDFUnicodeNotDefined, \
     mult_matrix, apply_matrix
from cmap import CMapDB
from extent import Rect, ExtSet, ExtGrid


##  PageItem
##
class PageItem:
  
  GRID_SIZE = 20
  
  def __init__(self, id, (x0,y0,x1,y1), rotate=0):
    self.id = id
    self.bbox = Rect(x0, y0, x1-x0, y1-y0)
    self.rotate = rotate
    self.grid = ExtGrid(self.GRID_SIZE)
    self.objs = []
    return
  
  def __repr__(self):
    bbox = self.bbox
    return ('<page id=%r bbox="%d,%d,%d,%d" rotate="%d">' %
            (self.id, bbox.x0,bbox.y0,bbox.x1,bbox.y1, self.rotate))
  
  def add(self, obj):
    self.objs.append(obj)
    self.grid.add(obj.bbox, obj)
    return
  
  def dump(self, outfp, codec):
    outfp.write(repr(self)+'\n')
    for obj in self.objs:
      obj.dump(outfp, codec)
    outfp.write('</page>\n')
    return

  def fuse(self):
    for obj1 in self.objs:
      f = (lambda obj: obj.bbox)
      for rect in obj1.search_range():
        neighbors = [ obj2 for obj2 in self.grid.get(rect, f) if obj2 is not obj1 ]
        #print obj1.bbox, obj1.text.encode('euc-jp','ignore'), rect, [ obj.bbox for obj in neighbors ]
    return


##  FigureItem
##
class FigureItem(PageItem):
  
  def __repr__(self):
    bbox = self.bbox
    return ('<figure id=%r bbox="%d,%d,%d,%d">' %
            (self.id, bbox.x0,bbox.y0,bbox.x1,bbox.y1))
  
  def dump(self, outfp, codec):
    outfp.write(repr(self)+'\n')
    for obj in self.objs:
      obj.dump(outfp, codec)
    outfp.write('</figure>\n')
    return

  def search_range(self):
    return []


##  TextItem
##
class TextItem:
  
  def __init__(self, matrix, font, size, width, text):
    self.matrix = matrix
    self.font = font
    (a,b,c,d,tx,ty) = self.matrix
    (self.width, self.size) = apply_matrix((a,b,c,d,0,0), (width,size))
    self.width = abs(self.width)
    self.origin = (tx,ty)
    self.direction = 0
    if not self.font.is_vertical():
      self.direction = 1
      (_,ascent) = apply_matrix((a,b,c,d,0,0), (0,font.ascent*size*0.001))
      (_,descent) = apply_matrix((a,b,c,d,0,0), (0,font.descent*size*0.001))
      self.bbox = Rect(tx, ty+descent, self.width, self.size)
    else:
      self.direction = 2
      mindisp = min( d for (d,_) in text )
      (mindisp,_) = apply_matrix((a,b,c,d,0,0), (mindisp*size*0.001,0))
      self.bbox = Rect(tx-mindisp, ty+self.width, self.size, self.width)
    self.text = ''.join( c for (_,c) in text )
    return
  
  def __repr__(self):
    return ('<text matrix=%r font=%r size=%r width=%r text=%r>' %
            (self.matrix, self.font, self.size, self.width, self.text))
  
  def dump(self, outfp, codec):
    (a,b,c,d,tx,ty) = self.matrix
    outfp.write('<text x="%.3f" y="%.3f" font=%r size="%.3f" width="%.3f">' %
                (tx, ty, self.font.fontname, self.size, self.width))
    outfp.write(self.text.encode(codec, 'xmlcharrefreplace'))
    outfp.write('</text>\n')
    return

  def search_range(self):
    if self.direction == 1:
      return [ Rect(self.bbox.x1, self.bbox.y0, self.size, self.size) ]
    else:
      return [ Rect(self.bbox.x0, self.bbox.y0-self.size, self.size, self.size) ]


##  TextConverter
##
class TextConverter(PDFDevice):

  def __init__(self, rsrc, debug=0):
    PDFDevice.__init__(self, rsrc, debug=debug)
    self.pages = []
    self.stack = []
    return

  def begin_page(self, page):
    self.context = PageItem(str(page.pageid), page.mediabox, page.rotate)
    return
  def end_page(self, _):
    assert not self.stack
    self.pages.append(self.context)
    return

  def begin_figure(self, name, bbox):
    self.stack.append(self.context)
    self.context = FigureItem(name, bbox)
    return
  def end_figure(self, _):
    fig = self.context
    self.context = self.stack.pop()
    self.context.add(fig)
    return

  def handle_undefined_char(self, cidcoding, cid):
    if self.debug:
      print >>stderr, 'undefined: %r, %r' % (cidcoding, cid)
    #return unichr(cid)
    return None

  def render_string(self, textstate, textmatrix, size, seq):
    font = textstate.font
    spwidth = int(-font.char_width(32) * 0.6) # space width
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
    item = TextItem(mult_matrix(textmatrix, self.ctm),
                    font, textstate.fontsize, size, text)
    self.context.add(item)
    return

  def dump(self, outfp, codec):
    outfp.write('<document>\n')
    for page in self.pages:
      #page.fuse()
      page.dump(outfp, codec)
    outfp.write('</document>\n')
    return


# pdf2txt
def pdf2txt(outfp, rsrc, fname, pages, codec, debug=0):
  device = TextConverter(rsrc, debug=debug)
  doc = PDFDocument(debug=debug)
  fp = file(fname)
  parser = PDFParser(doc, fp, debug=debug)
  interpreter = PDFPageInterpreter(rsrc, device, debug=debug)
  for (i,page) in enumerate(doc.get_pages(debug=debug)):
    if pages and (i not in pages): continue
    interpreter.process_page(page)
  fp.close()
  device.dump(outfp, codec)
  device.close()
  return


# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-c codec] [-p pages] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dp:c:')
  except getopt.GetoptError:
    return usage()
  if not args: return usage()
  debug = 0
  cmapdir = 'CMap'
  cdbcmapdir = 'CDBCMap'
  codec = 'ascii'
  pages = set()
  outfp = stdout
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-p': pages.add(int(v))
    elif k == '-o': outfp = file(v, 'wb')
    elif k == '-c': codec = v
  #
  CMapDB.initialize(cmapdir, cdbcmapdir, debug=debug)
  rsrc = PDFResourceManager(debug=debug)
  for fname in args:
    pdf2txt(outfp, rsrc, fname, pages, codec, debug=debug)
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
