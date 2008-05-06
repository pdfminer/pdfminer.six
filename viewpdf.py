#!/usr/bin/env python
import sys
from sgml import PDFSGMLParser, Document
stdout = sys.stdout
stderr = sys.stderr
try:
  import pygame
  from pygame.locals import *
except ImportError:
  print >>stderr, 'you need pygame'
  sys.exit(111)


def scale(x):
  return int(x*0.002)


##  FontManager
##
class FontManager:

  fonts = {}
  default_font = '/Library/Fonts/Vera.ttf'
  #default_font = '/Library/Fonts/ipag.ttf'
  
  @classmethod
  def get_font(klass, path, size):
    if not path:
      path = klass.default_font
    size = int(size)
    k = (path,size)
    if k not in klass.fonts:
      font = pygame.font.Font(path, size)
      klass.fonts[k] = font
    else:
      font = klass.fonts[k]
    return font


##  PDFViewer
##
class PDFViewer:

  BGCOLOR = (255,255,255)
  FGCOLOR = (0,0,0)

  def __init__(self, display, doc):
    self.display = display
    self.buf = None
    self.pages = doc.get_pages()
    self.render_page(0)
    return

  def render_page(self, pageno):
    print >>stderr, 'rendering: page=%d...' % pageno
    page = self.pages[pageno]
    (x,y,w,h) = page.bbox
    self.width = scale(w)
    self.height = scale(h)
    self.buf = pygame.Surface((self.width, self.height))
    self.buf.fill(self.BGCOLOR)
    for text in page.get_texts():
      font = FontManager.get_font(None, scale(text.size*0.7))
      (x,y,w,h) = text.bbox
      r = font.render(text.data, 1, self.FGCOLOR)
      self.buf.blit(r, (scale(x), self.height-scale(y)))
    self.pageno = pageno
    self.pos = (0,0)
    self.refresh()
    return

  def refresh(self):
    size = self.display.get_size()
    self.display.blit(self.buf, (0,0), (self.pos, size))
    pygame.display.flip()
    return

  STEP = 8
  def run(self):
    loop = True
    key = None
    (w,h) = self.display.get_size()
    xmax = self.width - w
    ymax = self.height - h
    while loop:
      for e in pygame.event.get():
        if e.type == VIDEOEXPOSE:
          self.refresh()
        elif e.type == KEYDOWN: 
          if e.key in (K_ESCAPE, K_RETURN, K_q):
            loop = False
            break
          elif e.key == K_SPACE:
            if self.pageno < len(self.pages)-1:
              self.render_page(self.pageno+1)
          elif e.key == K_b:
            if 0 < self.pageno:
              self.render_page(self.pageno-1)
          else:
            key = e.key
        elif e.type == KEYUP:
          key = None
      if key:
        (x,y) = self.pos
        if key in (K_h, K_LEFT, K_KP4):
          x = max(0, x-self.STEP)
        elif key in (K_l, K_RIGHT, K_KP6):
          x = min(xmax, x+self.STEP)
        elif key in (K_k, K_UP, K_KP8):
          y = max(0, y-self.STEP)
        elif key in (K_j, K_DOWN, K_KP2):
          y = min(ymax, y+self.STEP)
        self.pos = (x,y)
        self.refresh()
    return

# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-c encoding] file' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dc:P:')
  except getopt.GetoptError:
    return usage()
  if not args: return usage()
  debug = 0
  encoding = 'utf-8'
  cmapdir = 'CMap'
  cdbcmapdir = 'CDBCMap'
  password = ''
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-c': encoding = v
    elif k == '-P': password = v
  #
  fname = args.pop(0)
  if fname.endswith('.pdf'):
    # convert .pdf to sgml
    import tempfile
    from pdf2txt import CMapDB, PDFResourceManager, pdf2txt
    print >>stderr, 'reading %r...' % fname
    CMapDB.initialize(cmapdir, cdbcmapdir, debug=debug)
    rsrc = PDFResourceManager(debug=debug)
    fp = tempfile.TemporaryFile()
    pdf2txt(fp, rsrc, fname, None, encoding, password=password, debug=debug)
    fp.seek(0)
  else:
    fp = file(fname, 'rb')
  doc = Document()
  parser = PDFSGMLParser(doc)
  parser.feedfile(fp, encoding)
  parser.close()
  fp.close()
  #
  pygame.init()
  pygame.display.set_mode((640,480))
  PDFViewer(pygame.display.get_surface(), doc).run()
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
