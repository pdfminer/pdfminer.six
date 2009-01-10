#!/usr/bin/env python
import sys
stderr = sys.stderr
from struct import pack, unpack
try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO
from pdflib.psparser import PSLiteralTable, PSKeywordTable, PSLiteral, \
     literal_name, keyword_name, STRICT
from pdflib.pdftypes import PDFException, \
     resolve1, int_value, float_value, num_value, \
     str_value, list_value, dict_value, stream_value
from pdflib.cmap import CMap, CMapDB, CMapParser, FontMetricsDB, EncodingDB


##  Fonts
##

class PDFFontError(PDFException): pass
class PDFUnicodeNotDefined(PDFFontError): pass

LITERAL_STANDARD_ENCODING = PSLiteralTable.intern('StandardEncoding')


# PDFFont
class PDFFont(object):
  
  def __init__(self, descriptor, widths, default_width=None, font_matrix=None):
    self.descriptor = descriptor
    self.widths = widths
    self.fontname = descriptor.get('FontName', 'unknown')
    if isinstance(self.fontname, PSLiteral):
      self.fontname = literal_name(self.fontname)
    self.ascent = num_value(descriptor.get('Ascent', 0))
    self.descent = num_value(descriptor.get('Descent', 0))
    self.default_width = default_width or descriptor.get('MissingWidth', 0)
    self.leading = num_value(descriptor.get('Leading', 0))
    self.bbox = list_value(descriptor.get('FontBBox', (0,0,0,0)))
    self.font_matrix = font_matrix or (.001,0,0,.001,0,0)
    return

  def __repr__(self):
    return '<PDFFont>'

  def is_vertical(self):
    return False
  
  def is_multibyte(self):
    return False
  
  def decode(self, bytes):
    return map(ord, bytes)

  def char_width(self, cid):
    return self.widths.get(cid, self.default_width)

  def char_disp(self, cid):
    return 0
  
  def string_width(self, s):
    return sum( self.char_width(cid) for cid in self.decode(s) )

# PDFSimpleFont
class PDFSimpleFont(PDFFont):
  
  def __init__(self, descriptor, widths, spec, font_matrix=None):
    # Font encoding is specified either by a name of
    # built-in encoding or a dictionary that describes
    # the differences.
    if 'Encoding' in spec:
      encoding = resolve1(spec['Encoding'])
    else:
      encoding = LITERAL_STANDARD_ENCODING
    if isinstance(encoding, dict):
      name = literal_name(encoding.get('BaseEncoding', LITERAL_STANDARD_ENCODING))
      diff = list_value(encoding.get('Differences', None))
      self.encoding = EncodingDB.get_encoding(name, diff)
    else:
      self.encoding = EncodingDB.get_encoding(literal_name(encoding))
    self.ucs2_cmap = None
    if 'ToUnicode' in spec:
      strm = stream_value(spec['ToUnicode'])
      self.ucs2_cmap = CMap()
      CMapParser(self.ucs2_cmap, StringIO(strm.get_data())).run()
    PDFFont.__init__(self, descriptor, widths, font_matrix=font_matrix)
    return

  def to_unicode(self, cid):
    if not self.ucs2_cmap:
      try:
        return self.encoding[cid]
      except KeyError:
        raise PDFUnicodeNotDefined(None, cid)
    code = self.ucs2_cmap.tocode(cid)
    if not code:
      raise PDFUnicodeNotDefined(None, cid)
    chars = unpack('>%dH' % (len(code)/2), code)
    return ''.join( unichr(c) for c in chars )


# PDFType1Font
class PDFType1Font(PDFSimpleFont):
  
  def __init__(self, spec):
    try:
      self.basefont = literal_name(spec['BaseFont'])
    except KeyError:
      if STRICT:
        raise PDFFontError('BaseFont is missing')
      self.basefont = 'unknown'
    try:
      (descriptor, widths) = FontMetricsDB.get_metrics(self.basefont)
    except KeyError:
      descriptor = dict_value(spec.get('FontDescriptor', {}))
      firstchar = int_value(spec.get('FirstChar', 0))
      lastchar = int_value(spec.get('LastChar', 255))
      widths = list_value(spec.get('Widths', [0]*256))
      widths = dict( (i+firstchar,w) for (i,w) in enumerate(widths) )
    PDFSimpleFont.__init__(self, descriptor, widths, spec)
    return

  def __repr__(self):
    return '<PDFType1Font: basefont=%r>' % self.basefont

# PDFTrueTypeFont
class PDFTrueTypeFont(PDFType1Font):

  def __repr__(self):
    return '<PDFTrueTypeFont: basefont=%r>' % self.basefont

# PDFType3Font
class PDFType3Font(PDFSimpleFont):
  
  def __init__(self, spec):
    firstchar = int_value(spec.get('FirstChar', 0))
    lastchar = int_value(spec.get('LastChar', 0))
    widths = list_value(spec.get('Widths', [0]*256))
    widths = dict( (i+firstchar,w) for (i,w) in enumerate(widths))
    if 'FontDescriptor' in spec:
      descriptor = dict_value(spec['FontDescriptor'])
    else:
      descriptor = {'FontName':spec.get('Name'),
                    'Ascent':0, 'Descent':0,
                    'FontBBox':spec['FontBBox']}
    PDFSimpleFont.__init__(self, descriptor, widths, spec,
                           font_matrix=tuple(list_value(spec.get('FontMatrix'))))
    return

  def __repr__(self):
    return '<PDFType3Font>'


# PDFCIDFont

##  TrueTypeFont
##
class TrueTypeFont(object):

  class CMapNotFound(Exception): pass
  
  def __init__(self, name, fp):
    self.name = name
    self.fp = fp
    self.tables = {}
    fonttype = fp.read(4)
    (ntables, _1, _2, _3) = unpack('>HHHH', fp.read(8))
    for i in xrange(ntables):
      (name, tsum, offset, length) = unpack('>4sLLL', fp.read(16))
      self.tables[name] = (offset, length)
    return

  def create_cmap(self):
    if 'cmap' not in self.tables:
      raise TrueTypeFont.CMapNotFound
    (base_offset, length) = self.tables['cmap']
    fp = self.fp
    fp.seek(base_offset)
    (version, nsubtables) = unpack('>HH', fp.read(4))
    subtables = []
    for i in xrange(nsubtables):
      subtables.append(unpack('>HHL', fp.read(8)))
    char2gid = {}
    # Only supports subtable type 0, 2 and 4.
    for (_1, _2, st_offset) in subtables:
      fp.seek(base_offset+st_offset)
      (fmttype, fmtlen, fmtlang) = unpack('>HHH', fp.read(6))
      if fmttype == 0:
        char2gid.update(enumerate(unpack('>256B', fp.read(256))))
      elif fmttype == 2:
        subheaderkeys = unpack('>256H', fp.read(512))
        firstbytes = [0]*8192
        for (i,k) in enumerate(subheaderkeys):
          firstbytes[k/8] = i
        nhdrs = max(subheaderkeys)/8 + 1
        hdrs = []
        for i in xrange(nhdrs):
          (firstcode,entcount,delta,offset) = unpack('>HHhH', fp.read(8))
          hdrs.append((i,firstcode,entcount,delta,fp.tell()-2+offset))
        for (i,firstcode,entcount,delta,pos) in hdrs:
          if not entcount: continue
          first = firstcode + (firstbytes[i] << 8)
          fp.seek(pos)
          for c in xrange(entcount):
            gid = unpack('>H', fp.read(2))
            if gid:
              gid += delta
            char2gid[first+c] = gid
      elif fmttype == 4:
        (segcount, _1, _2, _3) = unpack('>HHHH', fp.read(8))
        segcount /= 2
        ecs = unpack('>%dH' % segcount, fp.read(2*segcount))
        fp.read(2)
        scs = unpack('>%dH' % segcount, fp.read(2*segcount))
        idds = unpack('>%dh' % segcount, fp.read(2*segcount))
        pos = fp.tell()
        idrs = unpack('>%dH' % segcount, fp.read(2*segcount))
        for (ec,sc,idd,idr) in zip(ecs, scs, idds, idrs):
          if idr:
            fp.seek(pos+idr)
            for c in xrange(sc, ec+1):
              char2gid[c] = (unpack('>H', fp.read(2))[0] + idd) & 0xffff
          else:
            for c in xrange(sc, ec+1):
              char2gid[c] = (c + idd) & 0xffff
    gid2char = dict( (gid, pack('>H', char))
                     for (char,gid) in char2gid.iteritems() )
    cmapname = 'Adobe-Identity-UCS-%s' % self.name
    return CMap(cmapname).update(char2gid, gid2char)

class PDFCIDFont(PDFFont):
  
  def __init__(self, spec):
    try:
      self.basefont = literal_name(spec['BaseFont'])
    except KeyError:
      if STRICT:
        raise PDFFontError('BaseFont is missing')
      self.basefont = 'unknown'
    self.cidsysteminfo = dict_value(spec.get('CIDSystemInfo', {}))
    self.cidcoding = '%s-%s' % (self.cidsysteminfo.get('Registry', 'unknown'),
                                self.cidsysteminfo.get('Ordering', 'unknown'))
    try:
      name = literal_name(spec['Encoding'])
    except KeyError:
      if STRICT:
        raise PDFFontError('Encoding is unspecified')
      name = 'unknown'
    try:
      self.cmap = CMapDB.get_cmap(name, strict=STRICT)
    except CMapDB.CMapNotFound, e:
      raise PDFFontError(e)
    try:
      descriptor = dict_value(spec['FontDescriptor'])
    except KeyError:
      if STRICT:
        raise PDFFontError('FontDescriptor is missing')
      descriptor = {}
    ttf = None
    if 'FontFile2' in descriptor:
      self.fontfile = stream_value(descriptor.get('FontFile2'))
      ttf = TrueTypeFont(self.basefont,
                         StringIO(self.fontfile.get_data()))
    self.ucs2_cmap = None
    if 'ToUnicode' in spec:
      strm = stream_value(spec['ToUnicode'])
      self.ucs2_cmap = CMap()
      CMapParser(self.ucs2_cmap, StringIO(strm.get_data())).run()
    elif self.cidcoding == 'Adobe-Identity':
      if ttf:
        try:
          self.ucs2_cmap = ttf.create_cmap()
        except TrueTypeFont.CMapNotFound:
          pass
    else:
      try:
        self.ucs2_cmap = CMapDB.get_cmap('%s-UCS2' % self.cidcoding,
                                         strict=STRICT)
      except CMapDB.CMapNotFound, e:
        raise PDFFontError(e)
    
    def get_width(seq):
      dic = {}
      char1 = char2 = None
      for v in seq:
        if char1 == None:
          char1 = v
        elif char2 == None and isinstance(v, int):
          char2 = v
        else:
          if char2 == None:
            for (i,w) in enumerate(v):
              dic[char1+i] = w
          else:
            for i in xrange(char1, char2+1):
              dic[i] = v
          char1 = char2 = None
      return dic
    self.vertical = self.cmap.is_vertical()
    if self.vertical:
      # writing mode: vertical
      dic = get_width(list_value(spec.get('W2', [])))
      widths = dict( (cid,w) for (cid,(d,w)) in dic.iteritems() )
      self.disps = dict( (cid,d) for (cid,(d,w)) in dic.iteritems() )
      (d,w) = spec.get('DW2', [880, -1000])
      default_width = w
      self.default_disp = d
    else:
      # writing mode: horizontal
      widths = get_width(list_value(spec.get('W', [])))
      self.disps = {}
      default_width = spec.get('DW', 1000)
      self.default_disp = 0
    PDFFont.__init__(self, descriptor, widths, default_width=default_width)
    return

  def __repr__(self):
    return '<PDFCIDFont: basefont=%r, cidcoding=%r>' % (self.basefont, self.cidcoding)
  
  def is_vertical(self):
    return self.vertical

  def is_multibyte(self):
    return True
  
  def decode(self, bytes):
    return self.cmap.decode(bytes)

  def char_disp(self, cid):
    return self.disps.get(cid, self.default_disp)

  def to_unicode(self, cid):
    if not self.ucs2_cmap:
      raise PDFUnicodeNotDefined(self.cidcoding, cid)
    code = self.ucs2_cmap.tocode(cid)
    if not code:
      raise PDFUnicodeNotDefined(self.cidcoding, cid)
    chars = unpack('>%dH' % (len(code)/2), code)
    return ''.join( unichr(c) for c in chars )


