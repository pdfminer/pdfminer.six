#!/usr/bin/env python
import sys
stdout = sys.stdout
stderr = sys.stderr
from pdfparser import PDFDocument, PDFParser
from pdfinterp import PDFDevice, PDFResourceManager, \
     PDFPageInterpreter, PDFUnicodeNotDefined, \
     mult_matrix, apply_matrix
from cmap import CMapDB


##  TextConverter
##
class TextConverter(PDFDevice):

  def __init__(self, outfp, rsrc, codec):
    PDFDevice.__init__(self, rsrc)
    self.outfp = outfp
    self.codec = codec
    return

  def close(self):
    self.outfp.write('\n')
    return
  
  def begin_page(self, page):
    (x0,y0,x1,y1) = page.mediabox
    self.outfp.write('<page id="%d" mediabox="%d,%d,%d,%d" rotate="%d">' %
                     (page.pageid, x0,y0,x1,y1, page.rotate))
    return
  def end_page(self, _):
    self.outfp.write('</page>\n')
    return

  def begin_figure(self, name, bbox):
    (x0,y0,x1,y1) = bbox
    self.outfp.write('<figure name="%s" bbox="%d,%d,%d,%d">\n' %
                     (name, x0,y0,x1,y1))
    return
  def end_figure(self, _):
    self.outfp.write('</figure>\n')
    return

  def handle_undefined_char(self, cidcoding, cid):
    return

  def render_string(self, textstate, textmatrix, size, seq):
    font = textstate.font
    spwidth = int(-font.char_width(32) * 0.6) # space width
    buf = ''
    for x in seq:
      if isinstance(x, int) or isinstance(x, float):
        if not font.is_vertical() and x <= spwidth:
          buf += ' '
      else:
        chars = font.decode(x)
        for cid in chars:
          try:
            char = font.to_unicode(cid)
            buf += char
          except PDFUnicodeNotDefined, e:
            (cidcoding, cid) = e.args
            s = self.handle_undefined_char(cidcoding, cid)
            if s:
              buf += s
    (a,b,c,d,tx,ty) = mult_matrix(textmatrix, self.ctm)
    if font.is_vertical():
      size = -size
      tag = 'vtext'
    else:
      tag = 'htext'
    if (b != 0 or c != 0 or a <= 0 or d <= 0):
      tag += ' skewed'
    s = buf.encode(self.codec, 'xmlcharrefreplace')
    (w,fs) = apply_matrix((a,b,c,d,0,0), (size,textstate.fontsize))
    def f(x): return '%.03f' % x
    self.outfp.write('<%s font="%s" size="%s" x="%s" y="%s" w="%s">%s</%s>\n' %
                     (tag, font.fontname, f(fs), f(tx), f(ty), f(w), s, tag))
    return


# pdf2txt
def pdf2txt(outfp, rsrc, fname, pages, codec, debug=0):
  device = TextConverter(outfp, rsrc, codec)
  outfp.write('<document>\n')
  doc = PDFDocument(debug=debug)
  fp = file(fname)
  parser = PDFParser(doc, fp, debug=debug)
  interpreter = PDFPageInterpreter(rsrc, device, debug=debug)
  for (i,page) in enumerate(doc.get_pages(debug=debug)):
    if pages and (i not in pages): continue
    interpreter.process_page(page)
  fp.close()
  outfp.write('</document>\n')
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
