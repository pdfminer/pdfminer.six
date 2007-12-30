#!/usr/bin/env python
import sys
from pdfparser import CMapDB, PDFDocument, PDFParser, dumpxml, PDFStream
stdout = sys.stdout
stderr = sys.stderr

# main
def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-d] [-v] [-a] [-b] [-p pageid] [-i objid] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'dvabi:p:')
  except getopt.GetoptError:
    return usage()
  if not args: return usage()
  (debug, verbose) = (0, 0)
  objids = []
  pageids = set()
  binary = False
  dumpall = False
  outfp = stdout
  for (k, v) in opts:
    if k == '-d': debug += 1
    elif k == '-v': verbose += 1
    elif k == '-i': objids.append(int(v))
    elif k == '-p': pageids.add(int(v))
    elif k == '-a': dumpall = True
    elif k == '-b': binary = True
    elif k == '-o': outfp = file(v, 'w')
  #
  for fname in args:
    doc = PDFDocument(debug=debug)
    fp = file(fname)
    parser = PDFParser(doc, fp, debug=debug)
    if objids:
      for objid in objids:
        obj = doc.getobj(objid)
        if binary:
          if isinstance(obj, PDFStream):
            outfp.write(obj.get_data())
          else:
            outfp.write(repr(obj))
        else:
          dumpxml(outfp, obj)
    elif pageids:
      for page in doc.get_pages():
        if page.pageid in pageids:
          dumpxml(outfp, page.attrs)
    elif dumpall:
      doc.dumpall(outfp)
    else:
      doc.dumptrailers(outfp)
    fp.close()
    outfp.write('\n')
  return

if __name__ == '__main__': sys.exit(main(sys.argv))
