from . import utils
from .pdffont import PDFUnicodeNotDefined


class PDFDevice:
    """Translate the output of PDFPageInterpreter to the output that is needed
    """

    def __init__(self, rsrcmgr):
        self.rsrcmgr = rsrcmgr
        self.ctm = None
        return

    def __repr__(self):
        return '<PDFDevice>'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

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

    def begin_page(self, page, ctm):
        return

    def end_page(self, page):
        return

    def begin_figure(self, name, bbox, matrix):
        return

    def end_figure(self, name):
        return

    def paint_path(self, graphicstate, stroke, fill, evenodd, path):
        return

    def render_image(self, name, stream):
        return

    def render_string(self, textstate, seq, ncs, graphicstate):
        return


class PDFTextDevice(PDFDevice):

    def render_string(self, textstate, seq, ncs, graphicstate):
        matrix = utils.mult_matrix(textstate.matrix, self.ctm)
        font = textstate.font
        fontsize = textstate.fontsize
        scaling = textstate.scaling * .01
        charspace = textstate.charspace * scaling
        wordspace = textstate.wordspace * scaling
        rise = textstate.rise
        if font.is_multibyte():
            wordspace = 0
        dxscale = .001 * fontsize * scaling
        if font.is_vertical():
            textstate.linematrix = self.render_string_vertical(
                seq, matrix, textstate.linematrix, font, fontsize,
                scaling, charspace, wordspace, rise, dxscale, ncs,
                graphicstate)
        else:
            textstate.linematrix = self.render_string_horizontal(
                seq, matrix, textstate.linematrix, font, fontsize,
                scaling, charspace, wordspace, rise, dxscale, ncs,
                graphicstate)
        return

    def render_string_horizontal(self, seq, matrix, pos,
                                 font, fontsize, scaling, charspace, wordspace,
                                 rise, dxscale, ncs, graphicstate):
        (x, y) = pos
        needcharspace = False
        for obj in seq:
            if utils.isnumber(obj):
                x -= obj*dxscale
                needcharspace = True
            else:
                for cid in font.decode(obj):
                    if needcharspace:
                        x += charspace
                    x += self.render_char(
                        utils.translate_matrix(matrix, (x, y)), font,
                        fontsize, scaling, rise, cid, ncs, graphicstate)
                    if cid == 32 and wordspace:
                        x += wordspace
                    needcharspace = True
        return (x, y)

    def render_string_vertical(self, seq, matrix, pos,
                               font, fontsize, scaling, charspace, wordspace,
                               rise, dxscale, ncs, graphicstate):
        (x, y) = pos
        needcharspace = False
        for obj in seq:
            if utils.isnumber(obj):
                y -= obj*dxscale
                needcharspace = True
            else:
                for cid in font.decode(obj):
                    if needcharspace:
                        y += charspace
                    y += self.render_char(
                        utils.translate_matrix(matrix, (x, y)), font, fontsize,
                        scaling, rise, cid, ncs, graphicstate)
                    if cid == 32 and wordspace:
                        y += wordspace
                    needcharspace = True
        return (x, y)

    def render_char(self, matrix, font, fontsize, scaling, rise, cid, ncs,
                    graphicstate):
        return 0


class TagExtractor(PDFDevice):

    def __init__(self, rsrcmgr, outfp, codec='utf-8'):
        PDFDevice.__init__(self, rsrcmgr)
        self.outfp = outfp
        self.codec = codec
        self.pageno = 0
        self._stack = []
        return

    def render_string(self, textstate, seq, ncs, graphicstate):
        font = textstate.font
        text = ''
        for obj in seq:
            if isinstance(obj, str):
                obj = utils.make_compat_bytes(obj)
            if not isinstance(obj, bytes):
                continue
            chars = font.decode(obj)
            for cid in chars:
                try:
                    char = font.to_unichr(cid)
                    text += char
                except PDFUnicodeNotDefined:
                    print(chars)
                    pass
        self.outfp.write(utils.enc(text))
        return

    def begin_page(self, page, ctm):
        output = '<page id="%s" bbox="%s" rotate="%d">' %\
                 (self.pageno, utils.bbox2str(page.mediabox), page.rotate)
        self.outfp.write(utils.make_compat_bytes(output))
        return

    def end_page(self, page):
        self.outfp.write(utils.make_compat_bytes('</page>\n'))
        self.pageno += 1
        return

    def begin_tag(self, tag, props=None):
        s = ''
        if isinstance(props, dict):
            s = ''.join(' {}="{}"'.format(utils.enc(k), utils.enc(str(v)))
                        for (k, v) in sorted(props.items()))
        out_s = '<{}{}>'.format(utils.enc(tag.name), s)
        self.outfp.write(utils.make_compat_bytes(out_s))
        self._stack.append(tag)
        return

    def end_tag(self):
        assert self._stack, str(self.pageno)
        tag = self._stack.pop(-1)
        out_s = '</%s>' % utils.enc(tag.name)
        self.outfp.write(utils.make_compat_bytes(out_s))
        return

    def do_tag(self, tag, props=None):
        self.begin_tag(tag, props)
        self._stack.pop(-1)
        return
