#!/usr/bin/env python
import sys
from pdfparser import PDFDocument, PDFParser, PDFPasswordIncorrect
from pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfdevice import PDFDevice, PDFPageAggregator
from layout import Page, LayoutContainer, TextItem, TextBox
from pdffont import PDFUnicodeNotDefined
from cmap import CMapDB


# e(x): encode string
def e(x, codec='ascii'):
  x = x.replace('&','&amp;').replace('>','&gt;').replace('<','&lt;').replace('"','&quot;')
  return x.encode(codec, 'xmlcharrefreplace')


##  PDFConverter
##
class PDFConverter(PDFPageAggregator):
  
  def __init__(self, rsrc, outfp, codec='ascii', cluster_margin=None):
    PDFPageAggregator.__init__(self, rsrc)
    self.cluster_margin = cluster_margin
    self.outfp = outfp
    self.codec = codec
    return

  def end_page(self, page):
    page = PDFPageAggregator.end_page(self, page)
    if self.cluster_margin:
      page.group_text(self.cluster_margin)
    return page

  def write(self, text):
    self.outfp.write(e(text, self.codec))
    return
  
  
##  TagExtractor
##
class TagExtractor(PDFDevice):

  def __init__(self, rsrc, outfp, codec='utf-8'):
    PDFDevice.__init__(self, rsrc)
    self.outfp = outfp
    self.codec = codec
    self.pageno = 0
    self.tag = None
    return
  
  def render_image(self, stream, size, matrix):
    return

  def render_string(self, textstate, textmatrix, seq):
    font = textstate.font
    text = ''
    for x in seq:
      if not isinstance(x, str): continue
      chars = font.decode(x)
      for cid in chars:
        try:
          char = font.to_unicode(cid)
          text += char
        except PDFUnicodeNotDefined, e:
          pass
    self.write(text)
    return

  def begin_page(self, page):
    (x0, y0, x1, y1) = page.mediabox
    bbox = '%.3f,%.3f,%.3f,%.3f' % (x0, y0, x1, y1)
    self.outfp.write('<page id="%s" bbox="%s" rotate="%d">' %
                     (self.pageno, bbox, page.rotate))
    return
  
  def end_page(self, page):
    self.outfp.write('</page>\n')
    self.pageno += 1
    return
  
  def begin_tag(self, tag, props=None):
    s = ''
    if props:
      s = ''.join( ' %s="%s"' % (e(k), e(str(v))) for (k,v)
                   in sorted(props.iteritems()) )
    self.outfp.write('<%s%s>' % (e(tag.name), s))
    self.tag = tag
    return
  
  def end_tag(self):
    assert self.tag
    self.outfp.write('</%s>' % e(self.tag.name))
    self.tag = None
    return
  
  def do_tag(self, tag, props=None):
    self.begin_tag(tag, props)
    self.tag = None
    return


##  SGMLConverter
##
class SGMLConverter(PDFConverter):

  def end_page(self, page):
    def draw(item):
      if isinstance(item, TextItem):
        self.outfp.write('<text font="%s" direction="%s" bbox="%s" fontsize="%.3f">' %
                         (e(item.font.fontname), item.get_direction(),
                          item.get_bbox(), item.fontsize))
        self.write(item.text)
        self.outfp.write('</text>\n')
      elif isinstance(item, LayoutContainer):
        self.outfp.write('<group id="%s" bbox="%s">\n' % (item.id, item.get_bbox()))
        for child in item:
          draw(child)
        self.outfp.write('</group>\n')
      return
    page = PDFConverter.end_page(self, page)
    self.outfp.write('<page id="%s" bbox="%s" rotate="%d">\n' %
                     (page.id, page.get_bbox(), page.rotate))
    draw(page)
    self.outfp.write('</page>\n')
    return


##  HTMLConverter
##
class HTMLConverter(PDFConverter):

  def __init__(self, rsrc, outfp, codec='utf-8', pagenum=True,
               pagepad=50, scale=1, cluster_margin=None):
    PDFConverter.__init__(self, rsrc, outfp, codec=codec, cluster_margin=cluster_margin)
    self.pagenum = pagenum
    self.pagepad = pagepad
    self.scale = scale
    self.outfp.write('<html><head>\n')
    self.outfp.write('<meta http-equiv="Content-Type" content="text/html; charset=%s">\n' %
                     self.codec)
    self.outfp.write('</head><body>\n')
    self.yoffset = self.pagepad
    self.show_text_border = False
    return

  def write_rect(self, color, x, y, w, h):
    self.outfp.write('<span style="position:absolute; border: 1px solid %s; '
                     'left:%dpx; top:%dpx; width:%dpx; height:%dpx;"></span>\n' % 
                     (color, x*self.scale, y*self.scale, w*self.scale, h*self.scale))
    return

  def end_page(self, page):
    def draw(item):
      if isinstance(item, Page):
        self.write_rect('gray', item.x0, self.yoffset-item.y1, item.width, item.height)
        if self.pagenum:
          self.outfp.write('<div style="position:absolute; top:%dpx;">' %
                           ((self.yoffset-page.y1)*self.scale))
          self.outfp.write('<a name="%s">Page %s</a></div>\n' % (page.id, page.id))
        for child in item:
          draw(child)
      elif isinstance(item, TextItem):
        if item.vertical:
          wmode = 'tb-rl'
        else:
          wmode = 'lr-tb'
        self.outfp.write('<span style="position:absolute; writing-mode:%s;'
                         ' left:%dpx; top:%dpx; font-size:%dpx;">' %
                         (wmode, item.x0*self.scale, (self.yoffset-item.y1)*self.scale,
                          item.fontsize*self.scale))
        self.write(item.text)
        self.outfp.write('</span>\n')
        if self.show_text_border:
          self.write_rect('red', item.x0, self.yoffset-item.y1, item.width, item.height)
      elif isinstance(item, LayoutContainer):
        self.write_rect('blue', item.x0, self.yoffset-item.y1, item.width, item.height)
        for child in item:
          draw(child)
      return
    page = PDFConverter.end_page(self, page)
    self.yoffset += page.y1
    draw(page)
    self.yoffset += self.pagepad
    return

  def close(self):
    self.outfp.write('<div style="position:absolute; top:0px;">Page: %s</div>\n' % 
                     ', '.join('<a href="#%s">%s</a>' % (i,i) for i in xrange(1,self.pageno)))
    self.outfp.write('</body></html>\n')
    return


##  TextConverter
##
class TextConverter(PDFConverter):

  def __init__(self, rsrc, outfp, codec='utf-8', pagenum=False,
               cluster_margin=None, word_margin=0.2):
    if cluster_margin == None:
      cluster_margin = 0.5
    PDFConverter.__init__(self, rsrc, outfp, codec=codec, cluster_margin=cluster_margin)
    self.pagenum = pagenum
    self.word_margin = word_margin
    return
  
  def end_page(self, page):
    def draw(item):
      if isinstance(item, TextItem):
        self.outfp.write(obj.text.encode(self.codec, 'replace'))
        self.outfp.write('\n')
      elif isinstance(item, TextBox):
        for line in item.get_lines(self.word_margin):
          self.outfp.write(line.encode(self.codec, 'replace')+'\n')
        self.outfp.write('\n')
      elif isinstance(item, LayoutContainer):
        for child in item:
          draw(child)
    page = PDFConverter.end_page(self, page)
    if self.pagenum:
      self.outfp.write('Page %d\n' % page.id)
    draw(page)
    self.outfp.write('\f')
    return

  def close(self):
    return


# pdf2txt
class TextExtractionNotAllowed(RuntimeError): pass

def convert(rsrc, device, fname, pagenos=None, maxpages=0, password=''):
  doc = PDFDocument()
  fp = file(fname, 'rb')
  parser = PDFParser(doc, fp)
  try:
    doc.initialize(password)
  except PDFPasswordIncorrect:
    raise TextExtractionNotAllowed('Incorrect password')
  if not doc.is_extractable:
    raise TextExtractionNotAllowed('Text extraction is not allowed: %r' % fname)
  interpreter = PDFPageInterpreter(rsrc, device)
  for (pageno,page) in enumerate(doc.get_pages()):
    if pagenos and (pageno not in pagenos): continue
    interpreter.process_page(page)
    if maxpages and maxpages <= pageno+1: break
  device.close()
  fp.close()
  return


# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-p pagenos] [-P password] [-c codec] [-w] [-t text|html|sgml|tag] [-o output] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dp:P:c:T:t:o:C:D:m:w')
  except getopt.GetoptError:
    return usage()
  if not args: return usage()
  debug = 0
  cmapdir = 'CMap'
  cdbcmapdir = 'CDBCMap'
  codec = 'ascii'
  pagenos = set()
  maxpages = 0
  outtype = 'html'
  password = ''
  pagenum = True
  splitwords = False
  cluster_margin = None
  outfp = sys.stdout
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-p': pagenos.update( int(x)-1 for x in v.split(',') )
    elif k == '-P': password = v
    elif k == '-c': codec = v
    elif k == '-m': maxpages = int(v)
    elif k == '-C': cmapdir = v
    elif k == '-D': cdbcmapdir = v
    elif k == '-T': cluster_margin = float(v)
    elif k == '-t': outtype = v
    elif k == '-o': outfp = file(v, 'wb')
    elif k == '-w': splitwords = True
  #
  CMapDB.debug = debug
  PDFResourceManager.debug = debug
  PDFDocument.debug = debug
  PDFParser.debug = debug
  PDFPageInterpreter.debug = debug
  #
  CMapDB.initialize(cmapdir, cdbcmapdir)
  rsrc = PDFResourceManager()
  if outtype == 'sgml':
    device = SGMLConverter(rsrc, outfp, codec=codec)
  elif outtype == 'html':
    device = HTMLConverter(rsrc, outfp, codec=codec, cluster_margin=cluster_margin)
  elif outtype == 'text':
    device = TextConverter(rsrc, outfp, codec=codec, cluster_margin=cluster_margin)
  elif outtype == 'tag':
    device = TagExtractor(rsrc, outfp, codec=codec)
  else:
    return usage()
  for fname in args:
    convert(rsrc, device, fname, pagenos, 
            maxpages=maxpages, password=password)
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
