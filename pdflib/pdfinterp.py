#!/usr/bin/env python
import sys
stderr = sys.stderr
from struct import pack, unpack
try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO
from psparser import PSException, PSSyntaxError, PSTypeError, PSEOF, \
     PSStackParser, PSLiteral, PSKeyword, STRICT, \
     PSLiteralTable, PSKeywordTable, literal_name, keyword_name
from pdfparser import PDFException, PDFObject, PDFStream, PDFObjRef, resolve1, \
     int_value, float_value, num_value, \
     str_value, list_value, dict_value, stream_value
from cmap import CMap, CMapDB, CMapParser, FontMetricsDB, EncodingDB
from utils import choplist


##  Exceptions
##
class PDFResourceError(PDFException): pass
class PDFInterpreterError(PDFException): pass
class PDFFontError(PDFException): pass
class PDFUnicodeNotDefined(PDFFontError): pass


##  ColorSpace
##
class ColorSpace(object):
  def __init__(self, name, ncomponents):
    self.name = name
    self.ncomponents = ncomponents
    return
  def __repr__(self):
    return '<ColorSpace: %s, ncomponents=%d>' % (self.name, self.ncomponents)


##  Constants
##
LITERAL_PDF = PSLiteralTable.intern('PDF')
LITERAL_TEXT = PSLiteralTable.intern('Text')
LITERAL_FONT = PSLiteralTable.intern('Font')
LITERAL_FORM = PSLiteralTable.intern('Form')
LITERAL_IMAGE = PSLiteralTable.intern('Image')
LITERAL_STANDARD_ENCODING = PSLiteralTable.intern('StandardEncoding')
LITERAL_DEVICE_GRAY = PSLiteralTable.intern('DeviceGray')
LITERAL_DEVICE_RGB = PSLiteralTable.intern('DeviceRGB')
LITERAL_DEVICE_CMYK = PSLiteralTable.intern('DeviceCMYK')
KEYWORD_BI = PSKeywordTable.intern('BI')
KEYWORD_ID = PSKeywordTable.intern('ID')
KEYWORD_EI = PSKeywordTable.intern('EI')
MATRIX_IDENTITY = (1, 0, 0, 1, 0, 0)

PREDEFINED_COLORSPACE = dict(
  (name, ColorSpace(name,n)) for (name,n) in {
  'CalRGB': 3,
  'CalGray': 1,
  'Lab': 3,
  'DeviceRGB': 3,
  'DeviceCMYK': 4,
  'DeviceGray': 1,
  'Separation': 1,
  'Indexed': 1,
  'Pattern': 1,
  }.iteritems())


##  Matrix operations
##
def mult_matrix((a1,b1,c1,d1,e1,f1), (a0,b0,c0,d0,e0,f0)):
  '''Multiplies two matrices.'''
  return (a0*a1+c0*b1,    b0*a1+d0*b1,
          a0*c1+c0*d1,    b0*c1+d0*d1,
          a0*e1+c0*f1+e0, b0*e1+d0*f1+f0)

def apply_matrix((a,b,c,d,e,f), (x,y)):
  '''Applies a matrix to coordinates.'''
  return (a*x+c*y+e, b*x+d*y+f)


##  Fonts
##

# PDFFont
class PDFFont(object):
  
  def __init__(self, descriptor, widths, default_width=None):
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
    return

  def __repr__(self):
    return '<PDFFont>'

  def is_vertical(self):
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
  
  def __init__(self, descriptor, widths, spec):
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
    PDFFont.__init__(self, descriptor, widths)
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
    PDFSimpleFont.__init__(self, descriptor, widths, spec)
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
        raise PDFFontError('Encoding not specified')
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
    PDFFont.__init__(self, descriptor, widths, default_width)
    return

  def __repr__(self):
    return '<PDFCIDFont: basefont=%r, cidcoding=%r>' % (self.basefont, self.cidcoding)
  
  def is_vertical(self):
    return self.vertical
  
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


##  Resource Manager
##
class PDFResourceManager(object):

  '''
  ResourceManager facilitates reuse of shared resources
  such as fonts, images and cmaps so that large objects are not
  allocated multiple times.
  '''
  
  def __init__(self, debug=0):
    self.debug = debug
    self.fonts = {}
    return

  def get_procset(self, procs):
    for proc in procs:
      if proc == LITERAL_PDF:
        pass
      elif proc == LITERAL_TEXT:
        pass
      else:
        #raise PDFResourceError('ProcSet %r is not supported.' % proc)
        pass
    return
  
  def get_cmap(self, name):
    return CMapDB.get_cmap(name, strict=STRICT)

  def get_font(self, objid, spec):
    if objid and objid in self.fonts:
      font = self.fonts[objid]
    else:
      if STRICT:
        if spec['Type'] != LITERAL_FONT:
          raise PDFFontError('Type is not /Font')
      # Create a Font object.
      if 'Subtype' in spec:
        subtype = literal_name(spec['Subtype'])
      else:
        if STRICT:
          raise PDFFontError('Font Subtype is not specified.')
        subtype = 'Type1'
      if subtype in ('Type1', 'MMType1'):
        # Type1 Font
        font = PDFType1Font(spec)
      elif subtype == 'TrueType':
        # TrueType Font
        font = PDFTrueTypeFont(spec)
      elif subtype == 'Type3':
        # Type3 Font
        font = PDFType3Font(spec)
      elif subtype in ('CIDFontType0', 'CIDFontType2'):
        # CID Font
        font = PDFCIDFont(spec)
      elif subtype == 'Type0':
        # Type0 Font
        dfonts = list_value(spec['DescendantFonts'])
        assert dfonts
        subspec = dict_value(dfonts[0]).copy()
        for k in ('Encoding', 'ToUnicode'):
          if k in spec:
            subspec[k] = resolve1(spec[k])
        font = self.get_font(None, subspec)
      else:
        if STRICT:
          raise PDFFontError('Invalid Font: %r' % spec)
        font = PDFType1Font(spec) # this is so wrong!
      if objid:
        self.fonts[objid] = font
    return font


##  PDFDevice
##
class PDFDevice(object):
  
  def __init__(self, rsrc, debug=0):
    self.rsrc = rsrc
    self.debug = debug
    self.ctm = None
    return
  
  def __repr__(self):
    return '<PDFDevice>'

  def close(self):
    return

  def set_ctm(self, ctm):
    self.ctm = ctm
    return

  def begin_tag(self, tag, props=None):
    return
  def end_tag(self):
    return
  def do_tag(self, tag, props=None):
    return

  def begin_page(self, page):
    return
  def end_page(self, page):
    return
  def begin_figure(self, name, bbox):
    return
  def end_figure(self, name):
    return
  
  def render_string(self, textstate, textmatrix, size, seq):
    raise NotImplementedError
  def render_image(self, stream, size, matrix):
    raise NotImplementedError


##  PDFContentParser
##
class PDFContentParser(PSStackParser):

  def __init__(self, streams, debug=0):
    self.streams = streams
    self.istream = 0
    PSStackParser.__init__(self, None, debug=debug)
    return

  def fillfp(self):
    if not self.fp:
      if self.istream < len(self.streams):
        strm = stream_value(self.streams[self.istream])
        self.istream += 1
      else:
        raise PSEOF
      self.fp = StringIO(strm.get_data())
    return

  def seek(self, pos):
    self.fillfp()
    PSStackParser.seek(self, pos)
    return

  def fillbuf(self):
    if self.charpos < len(self.buf): return
    while 1:
      self.fillfp()
      self.bufpos = self.fp.tell()
      self.buf = self.fp.read(self.BUFSIZ)
      if self.buf: break
      self.fp = None
    self.charpos = 0
    return

  def get_inline_data(self, pos, target='EI '):
    self.seek(pos)
    i = 0
    data = ''
    while i < len(target):
      self.fillbuf()
      if i:
        c = self.buf[self.charpos]
        data += c
        self.charpos += 1
        if c == target[i]:
          i += 1
        else:
          i = 0
      else:
        try:
          j = self.buf.index(target[0], self.charpos)
          #print 'found', (0, self.buf[j:j+10])
          data += self.buf[self.charpos:j]
          self.charpos = j+1
          i = 1
        except ValueError:
          data += self.buf[self.charpos:]
          self.charpos = len(self.buf)
    data = data[:-len(target)] # strip the last part
    return (pos, data)

  def flush(self):
    self.add_results(*self.popall())
    return

  def do_keyword(self, pos, token):
    if token == KEYWORD_BI:
      # inline image within a content stream
      self.start_type(pos, 'inline')
    elif token == KEYWORD_ID:
      try:
        (_, objs) = self.end_type('inline')
        if len(objs) % 2 != 0:
          raise PSTypeError('invalid dictionary construct: %r' % objs)
        d = dict( (literal_name(k), v) for (k,v) in choplist(2, objs) )
        (pos, data) = self.get_inline_data(pos+len('ID '))
        obj = PDFStream(d, data)
        self.push((pos, obj))
        self.push((pos, KEYWORD_EI))
      except PSTypeError:
        if STRICT: raise
    else:
      self.push((pos, token))
    return


##  Interpreter
##
class PDFPageInterpreter(object):
  
  class TextState(object):
    def __init__(self):
      self.font = None
      self.fontsize = 0
      self.charspace = 0
      self.wordspace = 0
      self.scaling = 100
      self.leading = 0
      self.render = 0
      self.rise = 0
      self.reset()
      return
    def __repr__(self):
      return ('<TextState: font=%r, fontsize=%r, charspace=%r, wordspace=%r, '
              ' scaling=%r, leading=%r, render=%r, rise=%r, '
              ' matrix=%r, linematrix=%r>' %
              (self.font, self.fontsize, self.charspace, self.wordspace, 
               self.scaling, self.leading, self.render, self.rise,
               self.matrix, self.linematrix))
    def reset(self):
      self.matrix = MATRIX_IDENTITY
      self.linematrix = (0, 0)
      return

  def __init__(self, rsrc, device, debug=0):
    self.rsrc = rsrc
    self.device = device
    self.debug = debug
    return

  def dup(self):
    return PDFPageInterpreter(self.rsrc, self.device, debug=self.debug)

  def init_resources(self, resources):
    self.fontmap = {}
    self.xobjmap = {}
    self.csmap = PREDEFINED_COLORSPACE.copy()
    # Handle resource declarations.
    def get_colorspace(spec):
      if isinstance(spec, list):
        name = literal_name(spec[0])
      else:
        name = literal_name(spec)
      if name == 'ICCBased' and isinstance(spec, list) and 2 <= len(spec):
        return ColorSpace(name, stream_value(spec[1]).dic['N'])
      elif name == 'DeviceN' and isinstance(spec, list) and 2 <= len(spec):
        return ColorSpace(name, len(list_value(spec[1])))
      else:
        return PREDEFINED_COLORSPACE[name]
    if resources:
      for (k,v) in dict_value(resources).iteritems():
        if 1 <= self.debug:
          print >>stderr, 'Resource: %r: %r' % (k,v)
        if k == 'Font':
          for (fontid,spec) in dict_value(v).iteritems():
            objid = None
            if isinstance(spec, PDFObjRef):
              objid = spec.objid
            spec = dict_value(spec)
            self.fontmap[fontid] = self.rsrc.get_font(objid, spec)
        elif k == 'ColorSpace':
          for (csid,spec) in dict_value(v).iteritems():
            self.csmap[csid] = get_colorspace(resolve1(spec))
        elif k == 'ProcSet':
          self.rsrc.get_procset(list_value(v))
        elif k == 'XObject':
          for (xobjid,xobjstrm) in dict_value(v).iteritems():
            self.xobjmap[xobjid] = xobjstrm
    return
  
  def init_state(self, ctm):
    # gstack: stack for graphical states.
    self.gstack = []
    self.ctm = ctm
    self.device.set_ctm(self.ctm)
    self.textstate = PDFPageInterpreter.TextState()
    # argstack: stack for command arguments.
    self.argstack = []
    # set some global states.
    self.scs = self.ncs = None
    if self.csmap:
      self.scs = self.ncs = self.csmap.values()[0]
    return

  def push(self, obj):
    self.argstack.append(obj)
    return

  def pop(self, n):
    x = self.argstack[-n:]
    self.argstack = self.argstack[:-n]
    return x

  def get_current_state(self):
    return (self.ctm, self.textstate)
  
  def set_current_state(self, state):
    (self.ctm, self.textstate) = state
    self.device.set_ctm(self.ctm)
    return

  # gsave
  def do_q(self):
    self.gstack.append(self.get_current_state())
    return
  # grestore
  def do_Q(self):
    if self.gstack:
      self.set_current_state(self.gstack.pop())
    return
  
  # concat-matrix
  def do_cm(self, a1, b1, c1, d1, e1, f1):
    self.ctm = mult_matrix((a1,b1,c1,d1,e1,f1), self.ctm)
    self.device.set_ctm(self.ctm)
    return
  
  # setlinewidth
  def do_w(self, width): return
  # setlinecap
  def do_J(self, cap): return
  # setlinejoin
  def do_j(self, join): return
  # setmiterlimit
  def do_M(self, limit): return
  # setdash
  def do_d(self, dash, phase): return
  # setintent
  def do_ri(self, intent): return
  # setflatness
  def do_i(self, flatness): return
  # savedict
  def do_gs(self, name): return
  
  # moveto
  def do_m(self, x, y): return
  # lineto
  def do_l(self, x, y): return
  # curveto
  def do_c(self, x1, y1, x2, y2, x3, y3): return
  # urveto
  def do_v(self, x2, y2, x3, y3): return
  # rveto
  def do_y(self, x1, y1, x3, y3): return
  # closepath
  def do_h(self): return
  # rectangle
  def do_re(self, x, y, w, h): return
  
  # stroke
  def do_S(self): return
  # close-and-stroke
  def do_s(self): return
  # fill
  def do_f(self): return
  # fill (obsolete)
  do_F = do_f
  # fill-even-odd
  def do_f_a(self): return
  # fill-and-stroke
  def do_B(self): return
  # fill-and-stroke-even-odd
  def do_B_a(self): return
  # close-fill-and-stroke
  def do_b(self): return
  # close-fill-and-stroke-even-odd
  def do_b_a(self): return
  # close-only
  def do_n(self): return
  # clip
  def do_W(self): return
  # clip-even-odd
  def do_W_a(self): return
  
  # setcolorspace-stroking
  def do_CS(self, name):
    self.scs = self.csmap[literal_name(name)]
    return
  # setcolorspace-non-strokine
  def do_cs(self, name):
    self.ncs = self.csmap[literal_name(name)]
    return
  # setgray-stroking
  def do_G(self, gray):
    self.do_CS(LITERAL_DEVICE_GRAY)
    return
  # setgray-non-stroking
  def do_g(self, gray):
    self.do_cs(LITERAL_DEVICE_GRAY)
    return
  # setrgb-stroking
  def do_RG(self, r, g, b):
    self.do_CS(LITERAL_DEVICE_RGB)
    return
  # setrgb-non-stroking
  def do_rg(self, r, g, b):
    self.do_cs(LITERAL_DEVICE_RGB)
    return
  # setcmyk-stroking
  def do_K(self, c, m, y, k):
    self.do_CS(LITERAL_DEVICE_CMYK)
    return
  # setcmyk-non-stroking
  def do_k(self, c, m, y, k):
    self.do_cs(LITERAL_DEVICE_CMYK)
    return

  # setcolor
  def do_SCN(self):
    if self.scs:
      n = self.scs.ncomponents
    else:
      if STRICT:
        raise PDFInterpreterError('no colorspace specified!')
      n = 1
    self.pop(n)
    return
  def do_scn(self):
    if self.ncs:
      n = self.ncs.ncomponents
    else:
      if STRICT:
        raise PDFInterpreterError('no colorspace specified!')
      n = 1
    self.pop(n)
    return
  def do_SC(self):
    self.do_SCN()
    return
  def do_sc(self):
    self.do_scn()
    return
    
  # sharing-name
  def do_sh(self, name): return
  
  # begin-text
  def do_BT(self):
    self.textstate.reset()
    return
  # end-text
  def do_ET(self):
    return

  # begin-compat
  def do_BX(self): return
  # end-compat
  def do_EX(self): return

  # marked content operators
  def do_MP(self, tag):
    self.device.do_tag(tag)
    return
  def do_DP(self, tag, props):
    self.device.do_tag(tag, props)
    return
  def do_BMC(self, tag):
    self.device.begin_tag(tag)
    return
  def do_BDC(self, tag, props):
    self.device.begin_tag(tag, props)
    return
  def do_EMC(self):
    self.device.end_tag()
    return

  # setcharspace
  def do_Tc(self, space):
    self.textstate.charspace = space
    return
  # setwordspace
  def do_Tw(self, space):
    self.textstate.wordspace = space
    return
  # textscale
  def do_Tz(self, scale):
    self.textstate.scaling = scale
    return
  # setleading
  def do_TL(self, leading):
    self.textstate.leading = -leading
    return
  # selectfont
  def do_Tf(self, fontid, fontsize):
    try:
      self.textstate.font = self.fontmap[literal_name(fontid)]
    except KeyError:
      if STRICT:
        raise PDFInterpreterError('Undefined font id: %r' % fontid)
      return
    self.textstate.fontsize = fontsize
    return
  # setrendering
  def do_Tr(self, render):
    self.textstate.render = render
    return
  # settextrise
  def do_Ts(self, rise):
    self.textstate.rise = rise
    return

  # text-move
  def do_Td(self, tx, ty):
    (a,b,c,d,e,f) = self.textstate.matrix
    self.textstate.matrix = (a,b,c,d,tx*a+ty*c+e,tx*b+ty*d+f)
    self.textstate.linematrix = (0, 0)
    #print >>stderr, 'Td(%r,%r): %r' % (tx,ty,self.textstate)
    return
  # text-move
  def do_TD(self, tx, ty):
    (a,b,c,d,e,f) = self.textstate.matrix
    self.textstate.matrix = (a,b,c,d,tx*a+ty*c+e,tx*b+ty*d+f)
    self.textstate.leading = ty
    self.textstate.linematrix = (0, 0)
    #print >>stderr, 'TD(%r,%r): %r' % (tx,ty,self.textstate)
    return
  # textmatrix
  def do_Tm(self, a,b,c,d,e,f):
    self.textstate.matrix = (a,b,c,d,e,f)
    self.textstate.linematrix = (0, 0)
    return
  # nextline
  def do_T_a(self):
    (a,b,c,d,e,f) = self.textstate.matrix
    self.textstate.matrix = (a,b,c,d,self.textstate.leading*c+e,self.textstate.leading*d+f)
    self.textstate.linematrix = (0, 0)
    return
  
  # show-pos
  def do_TJ(self, seq):
    #print >>stderr, 'TJ(%r): %r' % (seq,self.textstate)
    textstate = self.textstate
    font = textstate.font
    (a,b,c,d,e,f) = textstate.matrix
    (lx,ly) = textstate.linematrix
    s = ''.join( x for x in seq if isinstance(x, str) )
    n = sum( x for x in seq if not isinstance(x, str) )
    w = ((font.string_width(s)-n)/1000.0 * textstate.fontsize +
         len(s) * textstate.charspace +
         s.count(' ')*textstate.wordspace) * textstate.scaling / 100.0
    self.device.render_string(textstate, (a,b,c,d,e+lx,f+ly), w, seq)
    if font.is_vertical():
      ly += w
    else:
      lx += w
    textstate.linematrix = (lx,ly)
    return
  # show
  def do_Tj(self, s):
    self.do_TJ([s])
    return
  # quote
  def do__q(self, s):
    self.do_T_a()
    self.do_TJ([s])
    return
  # doublequote
  def do__w(self, aw, ac, s):
    self.do_Tw(aw)
    self.do_Tc(ac)
    self.do_TJ([s])
    return

  # inline image
  def do_BI(self): # never called
    return
  def do_ID(self): # never called
    return
  def do_EI(self, obj):
    return

  # invoke an XObject
  def do_Do(self, xobjid):
    xobjid = literal_name(xobjid)
    try:
      xobj = stream_value(self.xobjmap[xobjid])
    except KeyError:
      if STRICT:
        raise PDFInterpreterError('Undefined xobject id: %r' % xobjid)
      return
    if 1 <= self.debug:
      print >>stderr, 'Processing xobj: %r' % xobj
    subtype = xobj.dic.get('Subtype')
    if subtype == LITERAL_FORM and 'BBox' in xobj.dic:
      interpreter = self.dup()
      (x0,y0,x1,y1) = list_value(xobj.dic['BBox'])
      ctm = mult_matrix(list_value(xobj.dic.get('Matrix', MATRIX_IDENTITY)), self.ctm)
      (x0,y0) = apply_matrix(ctm, (x0,y0))
      (x1,y1) = apply_matrix(ctm, (x1,y1))
      bbox = (x0,y0,x1,y1)
      self.device.begin_figure(xobjid, bbox)
      interpreter.render_contents(dict_value(xobj.dic.get('Resources')), [xobj], ctm=ctm)
      self.device.end_figure(xobjid)
    elif subtype == LITERAL_IMAGE and 'Width' in xobj.dic and 'Height' in xobj.dic:
      (x0,y0) = apply_matrix(self.ctm, (0,0))
      (x1,y1) = apply_matrix(self.ctm, (1,1))
      self.device.begin_figure(xobjid, (x0,y0,x1,y1))
      (w,h) = (xobj.dic['Width'], xobj.dic['Height'])
      self.device.render_image(xobj, (w,h), self.ctm)
      self.device.end_figure(xobjid)
    else:
      # unsupported xobject type.
      pass
    return

  def process_page(self, page):
    if 1 <= self.debug:
      print >>stderr, 'Processing page: %r' % page
    self.device.begin_page(page)
    self.render_contents(page.resources, page.contents)
    self.device.end_page(page)
    return

  def render_contents(self, resources, contents, ctm=MATRIX_IDENTITY):
    self.init_resources(resources)
    self.init_state(ctm)
    self.execute(list_value(contents))
    return
  
  def execute(self, streams):
    parser = PDFContentParser(streams, debug=self.debug)
    while 1:
      try:
        (_,obj) = parser.nextobject()
      except PSEOF:
        break
      if isinstance(obj, PSKeyword):
        name = 'do_%s' % obj.name.replace('*','_a').replace('"','_w').replace("'",'_q')
        if hasattr(self, name):
          func = getattr(self, name)
          nargs = func.func_code.co_argcount-1
          if nargs:
            args = self.pop(nargs)
            if 1 <= self.debug:
              print >>stderr, 'exec: %s %r' % (obj.name, args)
            if len(args) == nargs:
              func(*args)
          else:
            if 1 <= self.debug:
              print >>stderr, 'exec: %s' % (obj.name)
            func()
        else:
          if STRICT:
            raise PDFInterpreterError('unknown operator: %r' % obj.name)
      else:
        self.push(obj)
    return
