#!/usr/bin/env python
import sys, os.path
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

def convert_cmap(files, cmapdir, cdbcmapdir, force=False):
  from cmap import CMapDB
  CMapDB.initialize(cmapdir)
  for fname in files:
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
    print 'usage: %s [-c cmapdir] [-C cdbcmapdir] [-f] file ...' % argv[0]
    return 100
  try:
    (opts, args) = getopt.getopt(argv[1:], 'c:C:f')
  except getopt.GetoptError:
    return usage()
  if not args: usage()
  cmapdir = 'CMap'
  cdbcmapdir = 'CDBCMap'
  force = False
  for (k, v) in opts:
    if k == '-f': force = True
    elif k == '-c': cmapdir = v
    elif k == '-C': cdbcmapdir = v
  if not os.path.isdir(cmapdir):
    raise ValueError('not directory: %r' % cmapdir)
  if not os.path.isdir(cdbcmapdir):
    raise ValueError('not directory: %r' % cdbcmapdir)
  return convert_cmap(args, cmapdir, cdbcmapdir, force=force)

if __name__ == '__main__': sys.exit(main(sys.argv))
