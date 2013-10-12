#!/usr/bin/env python2
import sys
import os.path
import gzip
import cPickle as pickle


##  CMapConverter
##
class CMapConverter(object):

    def __init__(self, check_codecs=[]):
        self.check_codecs = check_codecs
        self.code2cid = {} # {'cmapname': ...}
        self.is_vertical = {}
        self.cid2unichr_h = {} # {cid: unichr}
        self.cid2unichr_v = {} # {cid: unichr}
        return

    def load(self, fp):
        names = []
        for line in fp:
            (line,_,_) = line.strip().partition('#')
            if not line: continue
            values = line.split('\t')
            if not names:
                names = values
                continue
            d = dict( (k,v) for (k,v) in zip(names, values) if v != '*' )
            cid = int(d['CID'])
            for (key,value) in d.iteritems():
                if key == 'CID': continue
                self._register(cid, key, value)
        return

    def get_canonicals(self, name):
        if name.endswith('-H'):
            return (name, None)
        elif name == 'H':
            return ('H', 'V')
        else:
            return (name+'-H', name+'-V')

    def get_unichr(self, codes):
        # determine the "most popular" candidate.
        d = {}
        for code in codes:
            char = unicode(code, 'utf-8')
            if char not in d:
                d[char] = 0
            for codec in self.check_codecs:
                try:
                    char.encode(codec, 'strict')
                    d[char] += 1
                except UnicodeError:
                    pass
        chars = sorted(d.keys(), key=lambda char:d[char], reverse=True)
        return chars[0]

    def _register(self, cid, key, value):
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

        (hmapname, vmapname) = self.get_canonicals(key)
        if hmapname in self.code2cid:
            hmap = self.code2cid[hmapname]
        else:
            hmap = {}
            self.code2cid[hmapname] = hmap
        vmap = None
        if vmapname:
            self.is_vertical[vmapname] = True
            if vmapname in self.code2cid:
                vmap = self.code2cid[vmapname]
            else:
                vmap = {}
                self.code2cid[vmapname] = vmap
        
        hcodes = []
        vcodes = []
        for code in value.split(','):
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
            if key.endswith('-UTF8'):
                if hcodes:
                    self.cid2unichr_h[cid] = self.get_unichr(hcodes)
                if vcodes:
                    self.cid2unichr_v[cid] = self.get_unichr(vcodes)
        else:
            for code in hcodes:
                put(hmap, code, cid)
                put(vmap, code, cid)
            if key.endswith('-UTF8') and hcodes:
                code = self.get_unichr(hcodes)
                if cid not in self.cid2unichr_h:
                    self.cid2unichr_h[cid] = code
                if cid not in self.cid2unichr_v:
                    self.cid2unichr_v[cid] = code
        return

# main
def main(argv):

    def usage():
        print 'usage: %s output_dir regname cid2code.txt codecs ...' % argv[0]
        return 100
    
    args = argv[1:]
    if len(args) < 3: return usage()
    (outdir, regname, src) = args[:3]
    check_codecs = args[3:]

    print >>sys.stderr, 'reading %r...' % src
    converter = CMapConverter(check_codecs)
    fp = file(src)
    converter.load(fp)
    fp.close()

    for (name, cmap) in converter.code2cid.iteritems():
        fname = '%s.pickle.gz' % name
        print >>sys.stderr, 'writing %r...' % fname
        fp = gzip.open(os.path.join(outdir, fname), 'wb')
        data = dict(
            IS_VERTICAL=converter.is_vertical.get(name, False),
            CODE2CID=cmap,
        )
        fp.write(pickle.dumps(data))
        fp.close()

    fname = 'to-unicode-%s.pickle.gz' % regname
    print >>sys.stderr, 'writing %r...' % fname
    fp = gzip.open(os.path.join(outdir, fname), 'wb')
    data = dict(
        CID2UNICHR_H=converter.cid2unichr_h,
        CID2UNICHR_V=converter.cid2unichr_v,
    )
    fp.write(pickle.dumps(data))
    fp.close()
    return

if __name__ == '__main__': sys.exit(main(sys.argv))
