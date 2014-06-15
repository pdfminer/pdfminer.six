#!/usr/bin/env python
import sys
import fileinput

def main(argv):
    fonts = {}
    for line in fileinput.input():
        f = line.strip().split(' ')
        if not f: continue
        k = f[0]
        if k == 'FontName':
            fontname = f[1]
            props = {'FontName': fontname, 'Flags': 0}
            chars = {}
            fonts[fontname] = (props, chars)
        elif k == 'C':
            cid = int(f[1])
            if 0 <= cid and cid <= 255:
                width = int(f[4])
                chars[cid] = width
        elif k in ('CapHeight', 'XHeight', 'ItalicAngle',
                   'Ascender', 'Descender'):
            k = {'Ascender':'Ascent', 'Descender':'Descent'}.get(k,k)
            props[k] = float(f[1])
        elif k in ('FontName', 'FamilyName', 'Weight'):
            k = {'FamilyName':'FontFamily', 'Weight':'FontWeight'}.get(k,k)
            props[k] = f[1]
        elif k == 'IsFixedPitch':
            if f[1].lower() == 'true':
                props['Flags'] = 64
        elif k == 'FontBBox':
            props[k] = tuple(map(float, f[1:5]))
    print ('# -*- python -*-')
    print ('FONT_METRICS = {')
    for (fontname,(props,chars)) in fonts.iteritems():
        print (' %r: %r,' % (fontname, (props,chars)))
    print ('}')
    return 0

if __name__ == '__main__': sys.exit(main(sys.argv))
