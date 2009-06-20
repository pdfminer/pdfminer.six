#!/usr/bin/env python
import sys
from pdfminer.pdfparser import PDFDocument, PDFParser
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter, process_pdf
from pdfminer.pdfdevice import PDFDevice
from pdfminer.converter import SGMLConverter, HTMLConverter, TextConverter, TagExtractor
from pdfminer.cmap import CMapDB, find_cmap_path

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
  # debug option
  debug = 0
  # path option
  cmapdir = find_cmap_path()
  # input option
  password = ''
  pagenos = set()
  maxpages = 0
  # output option
  outfile = None
  outtype = None
  codec = 'utf-8'
  cluster_margin = None
  pageno = 1
  scale = 1
  showpageno = True
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-C': cmapdir = v
    elif k == '-P': password = v
    elif k == '-p': pagenos.update( int(x)-1 for x in v.split(',') )
    elif k == '-m': maxpages = int(v)
    elif k == '-t': outtype = v
    elif k == '-c': codec = v
    elif k == '-o': outfile = v
    elif k == '-s': scale = float(v)
    elif k == '-T': cluster_margin = float(v)
  #
  CMapDB.debug = debug
  PDFResourceManager.debug = debug
  PDFDocument.debug = debug
  PDFParser.debug = debug
  PDFPageInterpreter.debug = debug
  PDFDevice.debug = debug
  #
  CMapDB.initialize(cmapdir)
  rsrc = PDFResourceManager()
  if not outtype:
    outtype = 'text'
    if outfile:
      if outfile.endswith('.htm') or outfile.endswith('.html'):
        outtype = 'html'
      elif outfile.endswith('.sgml'):
        outtype = 'sgml'
      elif outfile.endswith('.tag'):
        outtype = 'tag'
  if outfile:
    outfp = file(outfile, 'w')
  else:
    outfp = sys.stdout
  if outtype == 'sgml':
    device = SGMLConverter(rsrc, outfp, codec=codec, cluster_margin=cluster_margin)
  elif outtype == 'html':
    device = HTMLConverter(rsrc, outfp, codec=codec, cluster_margin=cluster_margin, scale=scale)
  elif outtype == 'text':
    device = TextConverter(rsrc, outfp, codec=codec, cluster_margin=cluster_margin)
  elif outtype == 'tag':
    device = TagExtractor(rsrc, outfp, codec=codec)
  else:
    return usage()
  for fname in args:
    process_pdf(rsrc, device, fname, pagenos, maxpages=maxpages, password=password)
  device.close()
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
