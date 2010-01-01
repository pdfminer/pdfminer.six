#!/usr/bin/env python
import sys
import os.path

def process_cid2code(fp, check_codecs=[]):

    def get_canonicals(name):
        if name.endswith('-H'):
            return (name, None)
        elif name == 'H':
            return ('H', 'V')
        else:
            return (name+'-H', name+'-V')

    def get_unichr(codes):
        # determine the "most popular" candidate.
        d = {}
        for code in codes:
            char = unicode(code, 'utf-8')
            if char not in d:
                d[char] = 0
            for codec in check_codecs:
                try:
                    char.encode(codec, 'strict')
                    d[char] += 1
                except UnicodeError:
                    pass
        chars = sorted(d.keys(), key=lambda char:d[char], reverse=True)
        return chars[0]

    def put(dmap, code, cid, force=False):
        for b in code[:-1]:
            b = ord(b)
            if b in dmap:
                dmap = dmap[b]
            else:
                d = {}
                dmap[b] = d
                dmap = d
        b = ord(code[-1])
        if force or ((b not in dmap) or dmap[b] == cid):
            dmap[b] = cid
        return

    names = []
    code2cid = {} # {'cmapname': ...}
    is_vertical = {}
    cid2unichr_h = {} # {cid: unichr}
    cid2unichr_v = {} # {cid: unichr}
    
    for line in fp:
        line = line.strip()
        if line.startswith('#'): continue
        if line.startswith('CID'):
            names = line.split('\t')[1:]
            continue
        f = line.split('\t')
        if not f: continue
        cid = int(f[0])
        for (x,name) in zip(f[1:], names):
            if x == '*': continue
            (hmapname, vmapname) = get_canonicals(name)
            if hmapname in code2cid:
                hmap = code2cid[hmapname]
            else:
                hmap = {}
                code2cid[hmapname] = hmap
            vmap = None
            if vmapname:
                is_vertical[vmapname] = True
                if vmapname in code2cid:
                    vmap = code2cid[vmapname]
                else:
                    vmap = {}
                    code2cid[vmapname] = vmap
            hcodes = []
            vcodes = []
            for code in x.split(','):
                vertical = code.endswith('v')
                if vertical:
                    code = code[:-1]
                try:
                    code = code.decode('hex')
                except:
                    code = chr(int(code, 16))
                if vertical:
                    vcodes.append(code)
                else:
                    hcodes.append(code)
            if vcodes:
                assert vmap is not None
                for code in vcodes:
                    put(vmap, code, cid, True)
                for code in hcodes:
                    put(hmap, code, cid, True)
                if name.endswith('-UTF8'):
                    if hcodes:
                        cid2unichr_h[cid] = get_unichr(hcodes)
                    if vcodes:
                        cid2unichr_v[cid] = get_unichr(vcodes)
            else:
                for code in hcodes:
                    put(hmap, code, cid)
                    put(vmap, code, cid)
                if name.endswith('-UTF8') and hcodes:
                    code = get_unichr(hcodes)
                    if cid not in cid2unichr_h:
                        cid2unichr_h[cid] = code
                    if cid not in cid2unichr_v:
                        cid2unichr_v[cid] = code

    return (code2cid, is_vertical, cid2unichr_h, cid2unichr_v)

# main
def main(argv):

    def usage():
        print 'usage: %s output_dir regname cid2code.txt codecs ...' % argv[0]
        return 100
    
    def pyname(name):
        return name.replace('-','_')+'.py'

    args = argv[1:]
    if len(args) < 3: return usage()
    (outdir, regname, src) = args[:3]
    check_codecs = args[3:]

    print >>sys.stderr, 'reading %r...' % src
    fp = file(src)
    (code2cid, is_vertical, cid2unichr_h, cid2unichr_v) = process_cid2code(fp, check_codecs)
    fp.close()

    for (name, cmap) in code2cid.iteritems():
        fname = pyname(name)
        print >>sys.stderr, 'writing %r...' % fname
        fp = file(os.path.join(outdir, fname), 'w')
        print >>fp, '#!/usr/bin/env python'
        print >>fp, '#', fname
        print >>fp, 'IS_VERTICAL = %r' % is_vertical.get(name, False)
        print >>fp, 'CODE2CID = %r' % cmap
        fp.close()

    fname = 'TO_UNICODE_'+pyname(regname)
    print >>sys.stderr, 'writing %r...' % fname
    fp = file(os.path.join(outdir, fname), 'w')
    print >>fp, '#!/usr/bin/env python'
    print >>fp, '#', fname
    print >>fp, 'CID2UNICHR_H = %r' % cid2unichr_h
    print >>fp, 'CID2UNICHR_V = %r' % cid2unichr_v
    fp.close()

    return 0

if __name__ == '__main__': sys.exit(main(sys.argv))
