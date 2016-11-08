#!/usr/bin/env python

import sys
import fileinput

def main(argv):
    state = 0
    for line in fileinput.input():
        line = line.strip()
        if not line or line.startswith('#'):
            if state == 1:
                state = 2
                print ('}\n')
            print (line)
            continue
        if state == 0:
            print ('\nglyphname2unicode = {')
            state = 1
        (name,x) = line.split(';')
        codes = x.split(' ')
        print (' %r: u\'%s\',' % (name, ''.join( '\\u%s' % code for code in codes )))

if __name__ == '__main__': sys.exit(main(sys.argv))
