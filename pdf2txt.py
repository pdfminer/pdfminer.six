#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdfparser import PDFDocument, PDFParser, PDFPasswordIncorrect
from pdfinterp import PDFDevice, PDFResourceManager, \
     PDFPageInterpreter, PDFUnicodeNotDefined, \
     mult_matrix, apply_matrix
from cmap import CMapDB


##  PageItem
##
class PageItem:
  
  def __init__(self, id, (x0,y0,x1,y1), rotate=0):
    self.id = id
    self.bbox = (x0, y0, x1-x0, y1-y0)
    self.rotate = rotate
    self.objs = []
    return
  
  def __repr__(self):
    return ('<page id=%r bbox=%r rotate=%r>' % (self.id, self.bbox, self.rotate))
  
  def add(self, obj):
    self.objs.append(obj)
    return
  
  def dump(self, outfp, codec):
    bbox = '%.3f,%.3f,%.3f,%.3f' % self.bbox
    outfp.write('<page id="%s" bbox="%s" rotate="%d">\n' %
                (self.id, bbox, self.rotate))
    for obj in self.objs:
      obj.dump(outfp, codec)
    outfp.write('</page>\n')
    return


##  FigureItem
##
class FigureItem(PageItem):
  
  def __repr__(self):
    return ('<figure id=%r bbox=%r>' % (self.id, self.bbox))
  
  def dump(self, outfp, codec):
    bbox = '%.3f,%.3f,%.3f,%.3f' % self.bbox
    outfp.write('<figure id="%s" bbox="%s">\n' % (self.id, bbox))
    for obj in self.objs:
      obj.dump(outfp, codec)
    outfp.write('</figure>\n')
    return


##  TextItem
##
class TextItem:
  
  def __init__(self, matrix, font, fontsize, width, text):
    self.matrix = matrix
    self.font = font
    (a,b,c,d,tx,ty) = self.matrix
    (self.width, self.height) = apply_matrix((a,b,c,d,0,0), (width,fontsize))
    self.width = abs(self.width)
    self.origin = (tx,ty)
    self.direction = 0
    if not self.font.is_vertical():
      self.direction = 1
      (_,ascent) = apply_matrix((a,b,c,d,0,0), (0,font.ascent*fontsize*0.001))
      (_,descent) = apply_matrix((a,b,c,d,0,0), (0,font.descent*fontsize*0.001))
      self.bbox = (tx, ty+descent, self.width, self.height)
    else:
      self.direction = 2
      mindisp = min( d for (d,_) in text )
      (mindisp,_) = apply_matrix((a,b,c,d,0,0), (mindisp*fontsize*0.001,0))
      self.bbox = (tx-mindisp, ty+self.width, self.height, self.width)
    self.text = ''.join( c for (_,c) in text )
    (w,h) = apply_matrix((a,b,c,d,0,0), (fontsize,fontsize))
    self.fontsize = max(w,h)
    return
  
  def __repr__(self):
    return ('<text matrix=%r font=%r fontsize=%r width=%r height=%r text=%r>' %
            (self.matrix, self.font, self.fontsize, self.width, self.height, self.text))
  
  def dump(self, outfp, codec):
    def e(x):
      x = x.replace('&','&amp;').replace('>','&gt;').replace('<','&lt;')
      return x.encode(codec, 'xmlcharrefreplace')
    bbox = '%.3f,%.3f,%.3f,%.3f' % self.bbox
    outfp.write('<text font="%s" direction="%s" bbox="%s" fontsize="%.3f">' %
                (e(self.font.fontname), self.direction, bbox, self.fontsize))
    outfp.write(e(self.text))
    outfp.write('</text>\n')
    return


##  TextConverter
##
class TextConverter(PDFDevice):

  def __init__(self, rsrc, debug=0):
    PDFDevice.__init__(self, rsrc, debug=debug)
    self.reset()
    return

  def reset(self):
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

  def render_image(self, stream, size, matrix):
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
    for page in self.pages:
      page.dump(outfp, codec)
    return


# pdf2txt
class TextExtractionNotAllowed(RuntimeError): pass

def pdf2txt(outfp, rsrc, fname, pages, codec, password='', debug=0):
  device = TextConverter(rsrc, debug=debug)
  doc = PDFDocument(debug=debug)
  fp = file(fname, 'rb')
  parser = PDFParser(doc, fp, debug=debug)
  try:
    doc.initialize(password)
  except PDFPasswordIncorrect:
    raise TextExtractionNotAllowed('incorrect password')
  if not doc.is_extractable:
    raise TextExtractionNotAllowed('text extraction is not allowed: %r' % fname)
  interpreter = PDFPageInterpreter(rsrc, device, debug=debug)
  outfp.write('<document>\n')
  for (i,page) in enumerate(doc.get_pages(debug=debug)):
    if pages and (i not in pages): continue
    device.reset()
    interpreter.process_page(page)
    device.dump(outfp, codec)
  fp.close()
  device.close()
  outfp.write('</document>\n')
  return


# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-p pages] [-P password] [-c codec] [-o output] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dp:P:c:o:')
  except getopt.GetoptError:
    return usage()
  if not args: return usage()
  debug = 0
  cmapdir = 'CMap'
  cdbcmapdir = 'CDBCMap'
  codec = 'ascii'
  pages = set()
  password = ''
  outfp = stdout
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-p': pages.add(int(v))
    elif k == '-P': password = v
    elif k == '-c': codec = v
    elif k == '-o': outfp = file(v, 'wb')
  #
  CMapDB.initialize(cmapdir, cdbcmapdir, debug=debug)
  rsrc = PDFResourceManager(debug=debug)
  for fname in args:
    pdf2txt(outfp, rsrc, fname, pages, codec, password=password, debug=debug)
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
