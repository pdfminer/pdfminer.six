#!/usr/bin/env python
import sys, re
stderr = sys.stderr
from struct import pack, unpack
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from pdfminer.psparser import PSException, PSTypeError, PSEOF, \
     PSLiteralTable, PSKeywordTable, literal_name, keyword_name, \
     PSStackParser, PSKeyword, STRICT
from pdfminer.pdftypes import PDFException, PDFStream, PDFObjRef, \
     resolve1, int_value, float_value, num_value, \
     str_value, list_value, dict_value, stream_value
from pdfminer.utils import choplist, mult_matrix, MATRIX_IDENTITY
from pdfminer.pdffont import PDFFontError, PDFType1Font, PDFTrueTypeFont, PDFType3Font, PDFCIDFont
from pdfminer.pdfparser import PDFDocument, PDFParser, PDFPasswordIncorrect
from pdfminer.pdfcolor import PDFColorSpace, PREDEFINED_COLORSPACE, \
     LITERAL_DEVICE_GRAY, LITERAL_DEVICE_RGB, LITERAL_DEVICE_CMYK
from pdfminer.cmap import CMapDB


##  Exceptions
##
class PDFResourceError(PDFException): pass
class PDFInterpreterError(PDFException): pass


##  Constants
##
LITERAL_PDF = PSLiteralTable.intern('PDF')
LITERAL_TEXT = PSLiteralTable.intern('Text')
LITERAL_FONT = PSLiteralTable.intern('Font')
LITERAL_FORM = PSLiteralTable.intern('Form')
LITERAL_IMAGE = PSLiteralTable.intern('Image')


##  PDFTextState
##
class PDFTextState(object):

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
        # self.matrix is set
        # self.linematrix is set
        return

    def __repr__(self):
        return ('<PDFTextState: font=%r, fontsize=%r, charspace=%r, wordspace=%r, '
                ' scaling=%r, leading=%r, render=%r, rise=%r, '
                ' matrix=%r, linematrix=%r>' %
                (self.font, self.fontsize, self.charspace, self.wordspace,
                 self.scaling, self.leading, self.render, self.rise,
                 self.matrix, self.linematrix))

    def reset(self):
        self.matrix = MATRIX_IDENTITY
        self.linematrix = (0, 0)
        return


##  PDFGraphicState
##
class PDFGraphicState(object):

    def __init__(self):
        self.linewidth = 0
        self.linecap = None
        self.linejoin = None
        self.miterlimit = None
        self.dash = None
        self.intent = None
        self.flatness = None
        return

    def __repr__(self):
        return ('<PDFGraphicState: linewidth=%r, linecap=%r, linejoin=%r, '
                ' miterlimit=%r, dash=%r, intent=%r, flatness=%r>' %
                (self.linewidth, self.linecap, self.linejoin,
                 self.miterlimit, self.dash, self.intent, self.flatness))

##  Resource Manager
##
class PDFResourceManager(object):

    '''
    ResourceManager facilitates reuse of shared resources
    such as fonts and images so that large objects are not
    allocated multiple times.
    '''
    debug = 0

    def __init__(self):
        self.fonts = {}
        return

    def get_procset(self, procs):
        for proc in procs:
            if proc is LITERAL_PDF:
                pass
            elif proc is LITERAL_TEXT:
                pass
            else:
                #raise PDFResourceError('ProcSet %r is not supported.' % proc)
                pass
        return

    def get_cmap(self, cmapname, strict=False):
        return CMapDB.get_cmap(cmapname, strict=strict)

    def get_font(self, objid, spec):
        if objid and objid in self.fonts:
            font = self.fonts[objid]
        else:
            if STRICT:
                if spec['Type'] is not LITERAL_FONT:
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
                font = PDFType1Font(self, spec)
            elif subtype == 'TrueType':
                # TrueType Font
                font = PDFTrueTypeFont(self, spec)
            elif subtype == 'Type3':
                # Type3 Font
                font = PDFType3Font(self, spec)
            elif subtype in ('CIDFontType0', 'CIDFontType2'):
                # CID Font
                font = PDFCIDFont(self, spec)
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
                    raise PDFFontError('Invalid Font spec: %r' % spec)
                font = PDFType1Font(self, spec) # this is so wrong!
            if objid:
                self.fonts[objid] = font
        return font


##  PDFContentParser
##
class PDFContentParser(PSStackParser):

    def __init__(self, streams):
        self.streams = streams
        self.istream = 0
        PSStackParser.__init__(self, None)
        return

    def fillfp(self):
        if not self.fp:
            if self.istream < len(self.streams):
                strm = stream_value(self.streams[self.istream])
                self.istream += 1
            else:
                raise PSEOF('Unexpected EOF, file truncated?')
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

    def get_inline_data(self, pos, target='EI'):
        self.seek(pos)
        i = 0
        data = ''
        while i <= len(target):
            self.fillbuf()
            if i:
                c = self.buf[self.charpos]
                data += c
                self.charpos += 1
                if len(target) <= i and c.isspace():
                    i += 1
                elif i < len(target) and c == target[i]:
                    i += 1
                else:
                    i = 0
            else:
                try:
                    j = self.buf.index(target[0], self.charpos)
                    #print 'found', (0, self.buf[j:j+10])
                    data += self.buf[self.charpos:j+1]
                    self.charpos = j+1
                    i = 1
                except ValueError:
                    data += self.buf[self.charpos:]
                    self.charpos = len(self.buf)
        data = data[:-(len(target)+1)] # strip the last part
        data = re.sub(r'(\x0d\x0a|[\x0d\x0a])', '', data)
        return (pos, data)

    def flush(self):
        self.add_results(*self.popall())
        return

    KEYWORD_BI = PSKeywordTable.intern('BI')
    KEYWORD_ID = PSKeywordTable.intern('ID')
    KEYWORD_EI = PSKeywordTable.intern('EI')
    def do_keyword(self, pos, token):
        if token is self.KEYWORD_BI:
            # inline image within a content stream
            self.start_type(pos, 'inline')
        elif token is self.KEYWORD_ID:
            try:
                (_, objs) = self.end_type('inline')
                if len(objs) % 2 != 0:
                    raise PSTypeError('Invalid dictionary construct: %r' % objs)
                d = dict( (literal_name(k), v) for (k,v) in choplist(2, objs) )
                (pos, data) = self.get_inline_data(pos+len('ID '))
                obj = PDFStream(d, data)
                self.push((pos, obj))
                self.push((pos, self.KEYWORD_EI))
            except PSTypeError:
                if STRICT: raise
        else:
            self.push((pos, token))
        return


##  Interpreter
##
class PDFPageInterpreter(object):

    debug = 0

    def __init__(self, rsrc, device):
        self.rsrc = rsrc
        self.device = device
        return

    def dup(self):
        return PDFPageInterpreter(self.rsrc, self.device)

    # init_resources(resources):
    #   Prepare the fonts and XObjects listed in the Resource attribute.
    def init_resources(self, resources):
        self.fontmap = {}
        self.xobjmap = {}
        self.csmap = PREDEFINED_COLORSPACE.copy()
        if not resources: return
        def get_colorspace(spec):
            if isinstance(spec, list):
                name = literal_name(spec[0])
            else:
                name = literal_name(spec)
            if name == 'ICCBased' and isinstance(spec, list) and 2 <= len(spec):
                return PDFColorSpace(name, stream_value(spec[1]).dic['N'])
            elif name == 'DeviceN' and isinstance(spec, list) and 2 <= len(spec):
                return PDFColorSpace(name, len(list_value(spec[1])))
            else:
                return PREDEFINED_COLORSPACE[name]
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

    # init_state(ctm)
    #   Initialize the text and graphic states for rendering a page.
    def init_state(self, ctm):
        # gstack: stack for graphical states.
        self.gstack = []
        self.ctm = ctm
        self.device.set_ctm(self.ctm)
        self.textstate = PDFTextState()
        self.graphicstate = PDFGraphicState()
        self.curpath = []
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
        if n == 0: return []
        x = self.argstack[-n:]
        self.argstack = self.argstack[:-n]
        return x

    def get_current_state(self):
        return (self.ctm, self.textstate, self.graphicstate)

    def set_current_state(self, state):
        (self.ctm, self.textstate, self.graphicstate) = state
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
    def do_w(self, linewidth):
        self.graphicstate.linewidth = linewidth
        return
    # setlinecap
    def do_J(self, linecap):
        self.graphicstate.linecap = linecap
        return
    # setlinejoin
    def do_j(self, linejoin):
        self.graphicstate.linejoin = linejoin
        return
    # setmiterlimit
    def do_M(self, miterlimit):
        self.graphicstate.miterlimit = miterlimit
        return
    # setdash
    def do_d(self, dash, phase):
        self.graphicstate.dash = (dash, phase)
        return
    # setintent
    def do_ri(self, intent):
        self.graphicstate.intent = intent
        return
    # setflatness
    def do_i(self, flatness):
        self.graphicstate.flatness = flatness
        return
    # load-gstate
    def do_gs(self, name):
        #XXX
        return

    # moveto
    def do_m(self, x, y):
        self.curpath.append(('m',x,y))
        return
    # lineto
    def do_l(self, x, y):
        self.curpath.append(('l',x,y))
        return
    # curveto
    def do_c(self, x1, y1, x2, y2, x3, y3):
        self.curpath.append(('c',x1,y1,x2,y2,x3,y3))
        return
    # urveto
    def do_v(self, x2, y2, x3, y3):
        self.curpath.append(('v',x2,y2,x3,y3))
        return
    # rveto
    def do_y(self, x1, y1, x3, y3):
        self.curpath.append(('y',x1,y1,x3,y3))
        return
    # closepath
    def do_h(self):
        self.curpath.append(('h',))
        return
    # rectangle
    def do_re(self, x, y, w, h):
        self.curpath.append(('m',x,y))
        self.curpath.append(('l',x+w,y))
        self.curpath.append(('l',x+w,y+h))
        self.curpath.append(('l',x,y+h))
        self.curpath.append(('h',))
        return

    # stroke
    def do_S(self):
        self.device.paint_path(self.graphicstate, True, False, False, self.curpath)
        self.curpath = []
        return
    # close-and-stroke
    def do_s(self):
        self.do_h()
        self.do_S()
        return
    # fill
    def do_f(self):
        self.device.paint_path(self.graphicstate, False, True, False, self.curpath)
        self.curpath = []
        return
    # fill (obsolete)
    do_F = do_f
    # fill-even-odd
    def do_f_a(self):
        self.device.paint_path(self.graphicstate, False, True, True, self.curpath)
        self.curpath = []
        return
    # fill-and-stroke
    def do_B(self):
        self.device.paint_path(self.graphicstate, True, True, False, self.curpath)
        self.curpath = []
        return
    # fill-and-stroke-even-odd
    def do_B_a(self):
        self.device.paint_path(self.graphicstate, True, True, True, self.curpath)
        self.curpath = []
        return
    # close-fill-and-stroke
    def do_b(self):
        self.do_h()
        self.do_B()
        return
    # close-fill-and-stroke-even-odd
    def do_b_a(self):
        self.do_h()
        self.do_B_a()
        return
    # close-only
    def do_n(self):
        self.curpath = []
        return
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
        #self.do_CS(LITERAL_DEVICE_GRAY)
        return
    # setgray-non-stroking
    def do_g(self, gray):
        #self.do_cs(LITERAL_DEVICE_GRAY)
        return
    # setrgb-stroking
    def do_RG(self, r, g, b):
        #self.do_CS(LITERAL_DEVICE_RGB)
        return
    # setrgb-non-stroking
    def do_rg(self, r, g, b):
        #self.do_cs(LITERAL_DEVICE_RGB)
        return
    # setcmyk-stroking
    def do_K(self, c, m, y, k):
        #self.do_CS(LITERAL_DEVICE_CMYK)
        return
    # setcmyk-non-stroking
    def do_k(self, c, m, y, k):
        #self.do_cs(LITERAL_DEVICE_CMYK)
        return

    # setcolor
    def do_SCN(self):
        if self.scs:
            n = self.scs.ncomponents
        else:
            if STRICT:
                raise PDFInterpreterError('No colorspace specified!')
            n = 1
        self.pop(n)
        return
    def do_scn(self):
        if self.ncs:
            n = self.ncs.ncomponents
        else:
            if STRICT:
                raise PDFInterpreterError('No colorspace specified!')
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
                raise PDFInterpreterError('Undefined Font id: %r' % fontid)
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
        self.device.render_string(self.textstate, seq)
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
        if subtype is LITERAL_FORM and 'BBox' in xobj.dic:
            interpreter = self.dup()
            bbox = list_value(xobj.dic['BBox'])
            matrix = list_value(xobj.dic.get('Matrix', MATRIX_IDENTITY))
            self.device.begin_figure(xobjid, bbox, matrix)
            interpreter.render_contents(dict_value(xobj.dic.get('Resources')), [xobj], ctm=mult_matrix(matrix, self.ctm))
            self.device.end_figure(xobjid)
        elif subtype is LITERAL_IMAGE and 'Width' in xobj.dic and 'Height' in xobj.dic:
            self.device.begin_figure(xobjid, (0,0,1,1), MATRIX_IDENTITY)
            (w,h) = (xobj.dic['Width'], xobj.dic['Height'])
            self.device.render_image(xobj, (w,h))
            self.device.end_figure(xobjid)
        else:
            # unsupported xobject type.
            pass
        return

    def process_page(self, page):
        if 1 <= self.debug:
            print >>stderr, 'Processing page: %r' % page
        (x0,y0,x1,y1) = page.mediabox
        if page.rotate == 90:
            ctm = (0,-1,1,0, -y0,x1)
        elif page.rotate == 180:
            ctm = (-1,0,0,-1, x1,y1)
        elif page.rotate == 270:
            ctm = (0,1,-1,0, x0,-y1)
        else:
            ctm = (1,0,0,1, -x0,-y0)
        self.device.begin_page(page, ctm)
        self.render_contents(page.resources, page.contents, ctm=ctm)
        self.device.end_page(page)
        return

    # render_contents(resources, streams, ctm)
    #   Render the content streams.
    #   This method may be called recursively.
    def render_contents(self, resources, streams, ctm=MATRIX_IDENTITY):
        self.init_resources(resources)
        self.init_state(ctm)
        self.execute(list_value(streams))
        return

    def execute(self, streams):
        try:
            parser = PDFContentParser(streams)
        except PSEOF:
            # empty page
            return
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
                        raise PDFInterpreterError('Unknown operator: %r' % obj.name)
            else:
                self.push(obj)
        return


##  process_pdf
##
class PDFTextExtractionNotAllowed(PDFInterpreterError): pass

def process_pdf(rsrc, device, fp, pagenos=None, maxpages=0, password=''):
    doc = PDFDocument()
    parser = PDFParser(doc, fp)
    doc.initialize(password)
    if not doc.is_extractable:
        raise PDFTextExtractionNotAllowed('Text extraction is not allowed: %r' % fp)
    interpreter = PDFPageInterpreter(rsrc, device)
    for (pageno,page) in enumerate(doc.get_pages()):
        if pagenos and (pageno not in pagenos): continue
        interpreter.process_page(page)
        if maxpages and maxpages <= pageno+1: break
    return
