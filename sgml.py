#!/usr/bin/env python
import sys, sgmllib
__all__ = [ 'Document', 'Page', 'Text', 'PDFSGMLParser' ]

def fixed(x):
  return int(float(x)*1000)
def getbbox(s):
  (a,b,c,d) = s.split(',')
  return (fixed(a),fixed(b),fixed(c),fixed(d))


##  Document
##
class Document:
  
  def __init__(self):
    self.pages = []
    return

  def __repr__(self):
    return '<Document: pages=%r>' % self.pages

  def get_pages(self):
    return self.pages
  
  def add_page(self, page):
    self.pages.append(page)
    return
  
  def add_text(self, text):
    self.pages[-1].add_text(text)
    return


##  Page
##
class Page:
  
  def __init__(self, pageid, bbox, rotate):
    self.pageid = pageid
    self.bbox = bbox
    self.rotate = rotate
    self.texts = []
    return

  def __repr__(self):
    return '<Page(%s): texts=%r>' % (self.pageid, self.texts)
  
  def get_texts(self):
    return self.texts
  
  def add_text(self, text):
    self.texts.append(text)
    return


##  Text
##
class Text:
  
  def __init__(self, font, direction, bbox, size):
    self.font = font
    self.direction = direction
    self.bbox = bbox
    self.size = size
    self.data = ''
    return

  def __repr__(self):
    return '<Text: %r>' % (self.data)
  
  def add_data(self, data):
    self.data += data
    return


##  PDFSGMLParser
##
class PDFSGMLParser(sgmllib.SGMLParser):
  
  def __init__(self, doc):
    sgmllib.SGMLParser.__init__(self)
    self.doc = doc
    self.curtext = None
    return
  
  def start_document(self, attrs):
    return
  def end_document(self):
    return

  def start_page(self, attrs):
    attrs = dict(attrs)
    pageid = attrs['id']
    bbox = getbbox(attrs['bbox'])
    rotate = int(attrs['rotate'])
    page = Page(pageid, bbox, rotate)
    self.doc.add_page(page)
    return
  def end_page(self):
    return
  
  def start_text(self, attrs):
    attrs = dict(attrs)
    font = attrs['font']
    direction = attrs['direction']
    bbox = getbbox(attrs['bbox'])
    size = fixed(attrs['size'])
    text = Text(font, direction, bbox, size)
    self.curtext = text
    return
  def end_text(self):
    assert self.curtext
    self.doc.add_text(self.curtext)
    self.curtext = None
    return

  def handle_data(self, data):
    if not self.curtext: return
    self.curtext.add_data(data)
    return

  def feedfile(self, fp, encoding='utf-8'):
    for line in fp:
      line = unicode(line, encoding, 'ignore')
      self.feed(line)
    return


# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-c encoding] [file ...]' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dc:')
  except getopt.GetoptError:
    return usage()
  encoding = 'utf-8'
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-c': encoding = v
  for fname in args:
    doc = Document()
    parser = PDFSGMLParser(doc)
    parser.feedfile(fname, encoding)
    parser.close()
    print doc
  return 0

if __name__ == '__main__': sys.exit(main(sys.argv))
