#!/usr/bin/env python
import sys
from pdfparser import PDFDocument, PDFParser, PDFPasswordIncorrect
from pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfdevice import PDFDevice, PageItem, FigureItem, TextItem, PDFPageAggregator
from pdffont import PDFUnicodeNotDefined
from cmap import CMapDB


def enc(x, codec):
  x = x.replace('&','&amp;').replace('>','&gt;').replace('<','&lt;').replace('"','&quot;')
  return x.encode(codec, 'xmlcharrefreplace')

def encprops(props, codec):
  if not props: return ''
  return ''.join( ' %s="%s"' % (enc(k,codec), enc(str(v),codec)) for (k,v) in sorted(props.iteritems()) )

def get_textobjs(item, r=None):
  if r == None: r = []
  if isinstance(item, TextItem):
    r.append(item)
  elif isinstance(item, PageItem):
    for child in item.objs:
      get_textobjs(child, r)
  return r


##  PDFConverter
class PDFConverter(PDFPageAggregator):
  
  def __init__(self, rsrc, outfp, codec='ascii'):
    PDFPageAggregator.__init__(self, rsrc)
    self.outfp = outfp
    self.codec = codec
    return
  
  
##  SGMLConverter
##
class SGMLConverter(PDFConverter):

  def end_page(self, page):
    page = PDFConverter.end_page(self, page)
    def f(item):
      bbox = '%.3f,%.3f,%.3f,%.3f' % item.bbox
      if isinstance(item, FigureItem):
        self.outfp.write('<figure id="%s" bbox="%s">\n' % (item.id, bbox))
        for child in item.objs:
          f(child)
        self.outfp.write('</figure>\n')
      elif isinstance(item, TextItem):
        self.outfp.write('<text font="%s" direction="%s" bbox="%s" fontsize="%.3f">' %
                         (enc(item.font.fontname, self.codec), item.direction, bbox, item.fontsize))
        self.outfp.write(enc(item.text, self.codec))
        self.outfp.write('</text>\n')
    bbox = '%.3f,%.3f,%.3f,%.3f' % page.bbox
    self.outfp.write('<page id="%s" bbox="%s" rotate="%d">\n' %
                     (page.id, bbox, page.rotate))
    for child in page.objs:
      f(child)
    self.outfp.write('</page>\n')
    return


##  HTMLConverter
##
class HTMLConverter(PDFConverter):

  def __init__(self, rsrc, outfp, codec='utf-8', pagenum=True, pagepad=50, scale=1, cluster_margin=None):
    PDFConverter.__init__(self, rsrc, outfp, codec=codec)
    self.pagenum = pagenum
    self.pagepad = pagepad
    self.scale = scale
    self.outfp.write('<html><head><meta http-equiv="Content-Type" content="text/html; charset=%s">\n' % self.codec)
    self.outfp.write('</head><body>\n')
    self.yoffset = self.pagepad
    self.cluster_margin = cluster_margin
    self.show_text_border = False
    return
  
  def end_page(self, page):
    from cluster import cluster_pageobjs
    page = PDFConverter.end_page(self, page)
    (x0,y0,x1,y1) = page.bbox
    self.yoffset += y1
    if self.pagenum:
      self.outfp.write('<div style="position:absolute; top:%dpx;"><a name="%s">Page %s</a></div>' % 
                       ((self.yoffset-y1)*self.scale, page.id, page.id))
    self.outfp.write('<span style="position:absolute; border: 1px solid gray; '
                     'left:%dpx; top:%dpx; width:%dpx; height:%dpx;"></span>\n' % 
                     (x0*self.scale, (self.yoffset-y1)*self.scale, (x1-x0)*self.scale, (y1-y0)*self.scale))
    def draw(item):
      if isinstance(item, FigureItem):
        for child in item.objs:
          draw(child)
      elif isinstance(item, TextItem):
        if item.direction == 2:
          wmode = 'tb-rl'
        else:
          wmode = 'lr-tb'
        (x0,y0,x1,y1) = item.bbox
        self.outfp.write('<span style="position:absolute; writing-mode:%s; left:%dpx; top:%dpx; font-size:%dpx;">' %
                         (wmode, x0*self.scale, (self.yoffset-y1)*self.scale, item.fontsize*self.scale))
        self.outfp.write(enc(item.text, self.codec))
        self.outfp.write('</span>\n')
        if self.show_text_border:
          self.outfp.write('<span style="position:absolute; border: 1px solid red; '
                           'left:%dpx; top:%dpx; width:%dpx; height:%dpx;"></span>\n' % 
                           (x0*self.scale, (self.yoffset-y1)*self.scale, (x1-x0)*self.scale, (y1-y0)*self.scale))
    for child in page.objs:
      draw(child)
    if self.cluster_margin:
      clusters = cluster_pageobjs(get_textobjs(page), self.cluster_margin)
      for ((x0,y0,x1,y1),_,objs) in clusters:
        self.outfp.write('<span style="position:absolute; border: 1px solid red; '
                         'left:%dpx; top:%dpx; width:%dpx; height:%dpx;"></span>\n' % 
                       (x0*self.scale, (self.yoffset-y1)*self.scale, (x1-x0)*self.scale, (y1-y0)*self.scale))
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

  def __init__(self, rsrc, outfp, codec='utf-8', pagenum=False, cluster_margin=None):
    PDFConverter.__init__(self, rsrc, outfp, codec=codec)
    self.pagenum = pagenum
    if cluster_margin == None:
      cluster_margin = 0.5
    self.cluster_margin = cluster_margin
    return
  
  def end_page(self, page):
    from cluster import cluster_pageobjs
    page = PDFConverter.end_page(self, page)
    if self.pagenum:
      self.outfp.write('Page %d\n' % page.id)
    if self.cluster_margin:
      textobjs = get_textobjs(page)
      clusters = cluster_pageobjs(textobjs, self.cluster_margin)
      for (_,vertical,objs) in clusters:
        for (i,item) in enumerate(objs):
          (x0,y0,x1,y1) = item.bbox
          if (i and
              ((not vertical and (y1 < ly0 or ly1 < y0)) or
               (vertical and (x1 < lx0 or lx1 < x0)))):
            self.outfp.write('\n')
          (lx0,ly0,lx1,ly1) = (x0,y0,x1,y1)
          self.outfp.write(item.text.encode(self.codec, 'replace'))
        self.outfp.write('\n\n')
    else:
      for item in page.objs:
        if isinstance(item, TextItem):
          self.outfp.write(item.text.encode(self.codec, 'replace'))
          self.outfp.write('\n')
    self.outfp.write('\f')
    return

  def close(self):
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
    self.outfp.write(enc(text, self.codec))
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
    self.outfp.write('<%s%s>' % (enc(tag.name, self.codec), encprops(props, self.codec)))
    self.tag = tag
    return
  
  def end_tag(self):
    assert self.tag
    self.outfp.write('</%s>' % enc(self.tag.name, self.codec))
    self.tag = None
    return
  
  def do_tag(self, tag, props=None):
    self.outfp.write('<%s%s/>' % (enc(tag.name, self.codec), encprops(props, self.codec)))
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
