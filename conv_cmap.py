#!/usr/bin/env python
import sys
import fileinput
stdout = sys.stdout
stderr = sys.stderr

def dumpcdb(cmap, cdbfile, verbose=1):
  from struct import pack, unpack
  try:
    import cdb
  except ImportError:
    import pycdb as cdb
  m = cdb.cdbmake(cdbfile, cdbfile+'.tmp')
  if verbose:
    print >>stderr, 'Writing: %r...' % cdbfile
  for (k,v) in cmap.getall_attrs():
    m.add('/'+k, repr(v))
  for (code,cid) in cmap.getall_code2cid():
    m.add('c'+code, pack('>L',cid))
  for (cid,code) in cmap.getall_cid2code():
    m.add('i'+pack('>L',cid), code)
  m.finish()
  return

def convert_cmap(args, cmapdir='CMap', cdbcmapdir='CDBCMap', force=False):
  from pdfparser import CMapDB
  import os.path
  if not os.path.isdir(cmapdir):
    raise ValueError('not directory: %r' % cmapdir)
  if not os.path.isdir(cdbcmapdir):
    raise ValueError('not directory: %r' % cdbcmapdir)
  CMapDB.initialize(cmapdir)
  for fname in args:
    cmapname = os.path.basename(fname)
    cdbname = os.path.join(cdbcmapdir, cmapname+'.cmap.cdb')
    if not force and os.path.exists(cdbname):
      print >>stderr, 'Skipping: %r' % cdbname
      continue
    print >>stderr, 'Reading: %r...' % fname
    cmap = CMapDB.get_cmap(cmapname)
    dumpcdb(cmap, cdbname)
  return

def main(argv):
  import getopt
  def usage():
    print 'usage: %s [-C cmapdir] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'C:')
  except getopt.GetoptError:
    return usage()
  if not args: usage()
  cmapdir = 'CMap'
  for (k, v) in opts:
    if k == '-C': cmapdir = v
  return convert_cmap(args, cmapdir)

if __name__ == '__main__': sys.exit(main(sys.argv))
