#!/usr/bin/env python
import sys

def prof_main(argv):
  import getopt
  import hotshot, hotshot.stats
  def usage():
    print 'usage: %s output.prof mod.func [args ...]' % argv[0]
    return 100
  args = argv[1:]
  if len(args) < 2: return usage()
  prof = args.pop(0)
  name = args.pop(0)
  i = name.rindex('.')
  (modname, funcname) = (name[:i], name[i+1:])
  func = getattr(__import__(modname, fromlist=[modname]), funcname)
  if args:
    args.insert(0, argv[0])
    prof = hotshot.Profile(prof)
    prof.runcall(lambda : func(args))
    prof.close()
  else:
    stats = hotshot.stats.load(prof)
    stats.strip_dirs()
    stats.sort_stats('time', 'calls')
    stats.print_stats(1000)
  return
  
if __name__ == '__main__': sys.exit(prof_main(sys.argv))
