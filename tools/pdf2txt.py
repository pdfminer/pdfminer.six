#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdflib.pdfparser import PDFDocument, PDFParser, PDFPasswordIncorrect
from pdflib.pdfinterp import PDFDevice, PDFResourceManager, \
     PDFPageInterpreter, PDFUnicodeNotDefined, \
     mult_matrix, apply_matrix
from pdflib.cmap import CMapDB


def enc(x, codec):
  x = x.replace('&','&amp;').replace('>','&gt;').replace('<','&lt;')
  return x.encode(codec, 'xmlcharrefreplace')


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

  def __init__(self, rsrc, debug=0):
    PDFDevice.__init__(self, rsrc, debug=debug)
    self.reset()
    return

  def reset(self):
    self.pages = []
    self.stack = []
    return

  def begin_page(self, page):
    self.context = PageItem(str(page.pageid+1), page.mediabox, page.rotate)
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
    if text:
      item = TextItem(mult_matrix(textmatrix, self.ctm),
                      font, textstate.fontsize, size, text)
      self.context.add(item)
    return
  
  def dump_sgml(self, outfp, codec):
    def f(item):
      bbox = '%.3f,%.3f,%.3f,%.3f' % item.bbox
      if isinstance(item, FigureItem):
        outfp.write('<figure id="%s" bbox="%s">\n' % (item.id, bbox))
        for child in item.objs:
          f(child)
        outfp.write('</figure>\n')
      elif isinstance(item, TextItem):
        outfp.write('<text font="%s" direction="%s" bbox="%s" fontsize="%.3f">' %
                    (enc(item.font.fontname, codec), item.direction, bbox, item.fontsize))
        outfp.write(enc(item.text, codec))
        outfp.write('</text>\n')
    for page in self.pages:
      bbox = '%.3f,%.3f,%.3f,%.3f' % page.bbox
      outfp.write('<page id="%s" bbox="%s" rotate="%d">\n' %
                  (page.id, bbox, page.rotate))
      for child in page.objs:
        f(child)
      outfp.write('</page>\n')
    return

  def dump_html(self, outfp, codec, scale=1, pagepad=50, pagenum=True):
    offset = pagepad
    def f(item):
      if isinstance(item, FigureItem):
        pass
      elif isinstance(item, TextItem):
        if item.direction == 2:
          wmode = 'tb-rl'
        else:
          wmode = 'lr-tb'
        (x,_,_,y) = item.bbox
        outfp.write('<span style="position:absolute; writing-mode:%s; left:%dpx; top:%dpx; font-size:%dpx;">' %
                    (wmode, x*scale, (offset-y)*scale, item.fontsize*scale))
        outfp.write(enc(item.text, codec))
        outfp.write('</span>\n')
    outfp.write('<html><head><meta http-equiv="Content-Type" content="text/html; charset=%s">\n' % codec)
    outfp.write('</head><body>\n')
    if pagenum:
      outfp.write('<div>Page: %s</div>\n' % 
                  ', '.join('<a href="#%s">%s</a>' % (page.id,page.id) for page in self.pages ))
    for page in self.pages:
      (x0,y0,x1,y1) = page.bbox
      offset += y1
      if pagenum:
        outfp.write('<div style="position:absolute; top:%dpx;"><a name="%s">Page %s</a></div>' % 
                    ((offset-y1)*scale, page.id, page.id))
      outfp.write('<span style="position:absolute; border: 1px solid gray; '
                  'left:%dpx; top:%dpx; width:%dpx; height:%dpx;"></span>\n' % 
                  (x0*scale, (offset-y1)*scale, (x1-x0)*scale, (y1-y0)*scale))
      for child in page.objs:
        f(child)
      offset += pagepad
    outfp.write('</body></html>\n')
    return


# pdf2txt
class TextExtractionNotAllowed(RuntimeError): pass

def pdf2txt(outfp, rsrc, fname, pages, codec, maxpages=0, html=False, password='', debug=0):
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
  device.reset()
  for (i,page) in enumerate(doc.get_pages(debug=debug)):
    if pages and (i not in pages): continue
    interpreter.process_page(page)
    if maxpages and maxpages <= i+1: break
  if html:
    device.dump_html(outfp, codec)
  else:
    device.dump_sgml(outfp, codec)
  device.close()
  fp.close()
  return


# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-p pages] [-P password] [-c codec] [-H] [-o output] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dp:P:c:Ho:C:D:m:')
  except getopt.GetoptError:
    return usage()
  if not args: return usage()
  debug = 0
  cmapdir = 'CMap'
  cdbcmapdir = 'CDBCMap'
  codec = 'ascii'
  pages = set()
  maxpages = 0
  html = False
  password = ''
  outfp = stdout
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-p': pages.update( int(x)-1 for x in v.split(',') )
    elif k == '-P': password = v
    elif k == '-c': codec = v
    elif k == '-m': maxpages = int(v)
    elif k == '-C': cmapdir = v
    elif k == '-D': cdbcmapdir = v
    elif k == '-H': html = True
    elif k == '-o': outfp = file(v, 'wb')
  #
  CMapDB.initialize(cmapdir, cdbcmapdir, debug=debug)
  rsrc = PDFResourceManager(debug=debug)
  for fname in args:
    pdf2txt(outfp, rsrc, fname, pages, codec, 
            maxpages=maxpages, html=html, password=password, debug=debug)
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
