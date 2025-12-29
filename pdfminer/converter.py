import io
import logging
import re
from collections.abc import Sequence
from typing import (
    BinaryIO,
    ClassVar,
    Generic,
    TextIO,
    TypeVar,
    cast,
)

from pdfminer import utils
from pdfminer.image import ImageWriter
from pdfminer.layout import (
    LAParams,
    LTAnno,
    LTChar,
    LTComponent,
    LTContainer,
    LTCurve,
    LTFigure,
    LTImage,
    LTItem,
    LTLayoutContainer,
    LTLine,
    LTPage,
    LTRect,
    LTText,
    LTTextBox,
    LTTextBoxVertical,
    LTTextGroup,
    LTTextLine,
    TextGroupElement,
)
from pdfminer.pdfcolor import PDFColorSpace
from pdfminer.pdfdevice import PDFTextDevice
from pdfminer.pdfexceptions import PDFValueError
from pdfminer.pdffont import PDFFont, PDFUnicodeNotDefined
from pdfminer.pdfinterp import PDFGraphicState, PDFResourceManager
from pdfminer.pdfpage import PDFPage
from pdfminer.pdftypes import PDFStream
from pdfminer.utils import (
    AnyIO,
    Matrix,
    PathSegment,
    Point,
    Rect,
    apply_matrix_pt,
    apply_matrix_rect,
    bbox2str,
    enc,
    make_compat_str,
    mult_matrix,
)

log = logging.getLogger(__name__)


class PDFLayoutAnalyzer(PDFTextDevice):
    cur_item: LTLayoutContainer
    ctm: Matrix

    def __init__(
        self,
        rsrcmgr: PDFResourceManager,
        pageno: int = 1,
        laparams: LAParams | None = None,
    ) -> None:
        PDFTextDevice.__init__(self, rsrcmgr)
        self.pageno = pageno
        self.laparams = laparams
        self._stack: list[LTLayoutContainer] = []

    def begin_page(self, page: PDFPage, ctm: Matrix) -> None:
        (x0, y0, x1, y1) = apply_matrix_rect(ctm, page.mediabox)
        mediabox = (0, 0, abs(x0 - x1), abs(y0 - y1))
        self.cur_item = LTPage(self.pageno, mediabox)

    def end_page(self, page: PDFPage) -> None:
        assert not self._stack, str(len(self._stack))
        assert isinstance(self.cur_item, LTPage), str(type(self.cur_item))
        if self.laparams is not None:
            self.cur_item.analyze(self.laparams)
        self.pageno += 1
        self.receive_layout(self.cur_item)

    def begin_figure(self, name: str, bbox: Rect, matrix: Matrix) -> None:
        self._stack.append(self.cur_item)
        self.cur_item = LTFigure(name, bbox, mult_matrix(matrix, self.ctm))

    def end_figure(self, _: str) -> None:
        fig = self.cur_item
        assert isinstance(self.cur_item, LTFigure), str(type(self.cur_item))
        self.cur_item = self._stack.pop()
        self.cur_item.add(fig)

    def render_image(self, name: str, stream: PDFStream) -> None:
        assert isinstance(self.cur_item, LTFigure), str(type(self.cur_item))
        item = LTImage(
            name,
            stream,
            (self.cur_item.x0, self.cur_item.y0, self.cur_item.x1, self.cur_item.y1),
        )
        self.cur_item.add(item)

    def paint_path(
        self,
        gstate: PDFGraphicState,
        stroke: bool,
        fill: bool,
        evenodd: bool,
        path: Sequence[PathSegment],
    ) -> None:
        """Paint paths described in section 4.4 of the PDF reference manual"""
        shape = "".join(x[0] for x in path)

        if shape[:1] != "m":
            # Per PDF Reference Section 4.4.1, "path construction operators may
            # be invoked in any sequence, but the first one invoked must be m
            # or re to begin a new subpath." Since pdfminer.six already
            # converts all `re` (rectangle) operators to their equivalent
            # `mlllh` representation, paths ingested by `.paint_path(...)` that
            # do not begin with the `m` operator are invalid.
            pass

        elif shape.count("m") > 1:
            # recurse if there are multiple m's in this shape
            for m in re.finditer(r"m[^m]+", shape):
                subpath = path[m.start(0) : m.end(0)]
                self.paint_path(gstate, stroke, fill, evenodd, subpath)

        else:
            # Although the 'h' command does not not literally provide a
            # point-position, its position is (by definition) equal to the
            # subpath's starting point.
            #
            # And, per Section 4.4's Table 4.9, all other path commands place
            # their point-position in their final two arguments. (Any preceding
            # arguments represent control points on Bézier curves.)
            raw_pts = [
                cast(Point, p[-2:] if p[0] != "h" else path[0][-2:]) for p in path
            ]
            pts = [apply_matrix_pt(self.ctm, pt) for pt in raw_pts]

            operators = [str(operation[0]) for operation in path]
            transformed_points = [
                [
                    apply_matrix_pt(self.ctm, (float(operand1), float(operand2)))
                    for operand1, operand2 in zip(
                        operation[1::2], operation[2::2], strict=False
                    )
                ]
                for operation in path
            ]
            transformed_path = [
                cast(PathSegment, (o, *p))
                for o, p in zip(operators, transformed_points, strict=False)
            ]

            # Drop a redundant "l" on a path closed with "h"
            if len(shape) > 3 and shape[-2:] == "lh" and pts[-2] == pts[0]:
                shape = shape[:-2] + "h"
                pts.pop()

            if shape in {"mlh", "ml"}:
                # single line segment
                #
                # Note: 'ml', in conditional above, is a frequent anomaly
                # that we want to support.
                line = LTLine(
                    gstate.linewidth,
                    pts[0],
                    pts[1],
                    stroke,
                    fill,
                    evenodd,
                    gstate.scolor,
                    gstate.ncolor,
                    original_path=transformed_path,
                    dashing_style=gstate.dash,
                )
                self.cur_item.add(line)

            elif shape in {"mlllh", "mllll"}:
                (x0, y0), (x1, y1), (x2, y2), (x3, y3), _ = pts

                is_closed_loop = pts[0] == pts[4]
                has_square_coordinates = (
                    x0 == x1 and y1 == y2 and x2 == x3 and y3 == y0
                ) or (y0 == y1 and x1 == x2 and y2 == y3 and x3 == x0)
                if is_closed_loop and has_square_coordinates:
                    rect = LTRect(
                        gstate.linewidth,
                        (*pts[0], *pts[2]),
                        stroke,
                        fill,
                        evenodd,
                        gstate.scolor,
                        gstate.ncolor,
                        transformed_path,
                        gstate.dash,
                    )
                    self.cur_item.add(rect)
                else:
                    curve = LTCurve(
                        gstate.linewidth,
                        pts,
                        stroke,
                        fill,
                        evenodd,
                        gstate.scolor,
                        gstate.ncolor,
                        transformed_path,
                        gstate.dash,
                    )
                    self.cur_item.add(curve)
            else:
                curve = LTCurve(
                    gstate.linewidth,
                    pts,
                    stroke,
                    fill,
                    evenodd,
                    gstate.scolor,
                    gstate.ncolor,
                    transformed_path,
                    gstate.dash,
                )
                self.cur_item.add(curve)

    def render_char(
        self,
        matrix: Matrix,
        font: PDFFont,
        fontsize: float,
        scaling: float,
        rise: float,
        cid: int,
        ncs: PDFColorSpace,
        graphicstate: PDFGraphicState,
    ) -> float:
        try:
            text = font.to_unichr(cid)
            assert isinstance(text, str), str(type(text))
        except PDFUnicodeNotDefined:
            text = self.handle_undefined_char(font, cid)
        textwidth = font.char_width(cid)
        textdisp = font.char_disp(cid)
        item = LTChar(
            matrix,
            font,
            fontsize,
            scaling,
            rise,
            text,
            textwidth,
            textdisp,
            ncs,
            graphicstate,
        )
        self.cur_item.add(item)
        return item.adv

    def handle_undefined_char(self, font: PDFFont, cid: int) -> str:
        log.debug(f"undefined: {font!r}, {cid!r}")
        return f"(cid:{cid})"

    def receive_layout(self, ltpage: LTPage) -> None:
        pass


class PDFPageAggregator(PDFLayoutAnalyzer):
    def __init__(
        self,
        rsrcmgr: PDFResourceManager,
        pageno: int = 1,
        laparams: LAParams | None = None,
    ) -> None:
        PDFLayoutAnalyzer.__init__(self, rsrcmgr, pageno=pageno, laparams=laparams)
        self.result: LTPage | None = None

    def receive_layout(self, ltpage: LTPage) -> None:
        self.result = ltpage

    def get_result(self) -> LTPage:
        assert self.result is not None
        return self.result


# Some PDFConverter children support only binary I/O
IOType = TypeVar("IOType", TextIO, BinaryIO, AnyIO)


class PDFConverter(PDFLayoutAnalyzer, Generic[IOType]):
    def __init__(
        self,
        rsrcmgr: PDFResourceManager,
        outfp: IOType,
        codec: str = "utf-8",
        pageno: int = 1,
        laparams: LAParams | None = None,
    ) -> None:
        PDFLayoutAnalyzer.__init__(self, rsrcmgr, pageno=pageno, laparams=laparams)
        self.outfp: IOType = outfp
        self.codec = codec
        self.outfp_binary = self._is_binary_stream(self.outfp)

    @staticmethod
    def _is_binary_stream(outfp: AnyIO) -> bool:
        """Test if an stream is binary or not"""
        if "b" in getattr(outfp, "mode", ""):
            return True
        elif hasattr(outfp, "mode"):
            # output stream has a mode, but it does not contain 'b'
            return False
        elif isinstance(outfp, io.BytesIO):
            return True
        elif isinstance(outfp, (io.StringIO, io.TextIOBase)):
            return False

        return True


class TextConverter(PDFConverter[AnyIO]):
    def __init__(
        self,
        rsrcmgr: PDFResourceManager,
        outfp: AnyIO,
        codec: str = "utf-8",
        pageno: int = 1,
        laparams: LAParams | None = None,
        showpageno: bool = False,
        imagewriter: ImageWriter | None = None,
    ) -> None:
        super().__init__(rsrcmgr, outfp, codec=codec, pageno=pageno, laparams=laparams)
        self.showpageno = showpageno
        self.imagewriter = imagewriter

    def write_text(self, text: str) -> None:
        text = utils.compatible_encode_method(text, self.codec, "ignore")
        if self.outfp_binary:
            cast(BinaryIO, self.outfp).write(text.encode())
        else:
            cast(TextIO, self.outfp).write(text)

    def receive_layout(self, ltpage: LTPage) -> None:
        def render(item: LTItem) -> None:
            if isinstance(item, LTContainer):
                for child in item:
                    render(child)
            elif isinstance(item, LTText):
                self.write_text(item.get_text())
            if isinstance(item, LTTextBox):
                self.write_text("\n")
            elif isinstance(item, LTImage) and self.imagewriter is not None:
                self.imagewriter.export_image(item)

        if self.showpageno:
            self.write_text(f"Page {ltpage.pageid}\n")
        render(ltpage)
        self.write_text("\f")

    # Some dummy functions to save memory/CPU when all that is wanted
    # is text.  This stops all the image and drawing output from being
    # recorded and taking up RAM.
    def render_image(self, name: str, stream: PDFStream) -> None:
        if self.imagewriter is not None:
            PDFConverter.render_image(self, name, stream)

    def paint_path(
        self,
        gstate: PDFGraphicState,
        stroke: bool,
        fill: bool,
        evenodd: bool,
        path: Sequence[PathSegment],
    ) -> None:
        pass


class HTMLConverter(PDFConverter[AnyIO]):
    RECT_COLORS: ClassVar[dict[str, str]] = {
        "figure": "yellow",
        "textline": "magenta",
        "textbox": "cyan",
        "textgroup": "red",
        "curve": "black",
        "page": "gray",
    }

    TEXT_COLORS: ClassVar[dict[str, str]] = {
        "textbox": "blue",
        "char": "black",
    }

    def __init__(
        self,
        rsrcmgr: PDFResourceManager,
        outfp: AnyIO,
        codec: str = "utf-8",
        pageno: int = 1,
        laparams: LAParams | None = None,
        scale: float = 1,
        fontscale: float = 1.0,
        layoutmode: str = "normal",
        showpageno: bool = True,
        pagemargin: int = 50,
        imagewriter: ImageWriter | None = None,
        debug: int = 0,
        rect_colors: dict[str, str] | None = None,
        text_colors: dict[str, str] | None = None,
    ) -> None:
        PDFConverter.__init__(
            self,
            rsrcmgr,
            outfp,
            codec=codec,
            pageno=pageno,
            laparams=laparams,
        )

        # write() assumes a codec for binary I/O, or no codec for text I/O.
        if self.outfp_binary and not self.codec:
            raise PDFValueError("Codec is required for a binary I/O output")
        if not self.outfp_binary and self.codec:
            raise PDFValueError("Codec must not be specified for a text I/O output")

        if text_colors is None:
            text_colors = {"char": "black"}
        if rect_colors is None:
            rect_colors = {"curve": "black", "page": "gray"}

        self.scale = scale
        self.fontscale = fontscale
        self.layoutmode = layoutmode
        self.showpageno = showpageno
        self.pagemargin = pagemargin
        self.imagewriter = imagewriter
        self.rect_colors = rect_colors
        self.text_colors = text_colors
        if debug:
            self.rect_colors.update(self.RECT_COLORS)
            self.text_colors.update(self.TEXT_COLORS)
        self._yoffset: float = self.pagemargin
        self._font: tuple[str, float] | None = None
        self._fontstack: list[tuple[str, float] | None] = []
        self.write_header()

    def write(self, text: str) -> None:
        if self.codec:
            cast(BinaryIO, self.outfp).write(text.encode(self.codec))
        else:
            cast(TextIO, self.outfp).write(text)

    def write_header(self) -> None:
        self.write("<html><head>\n")
        if self.codec:
            s = (
                '<meta http-equiv="Content-Type" content="text/html; '
                f'charset={self.codec}">\n'
            )
        else:
            s = '<meta http-equiv="Content-Type" content="text/html">\n'
        self.write(s)
        self.write("</head><body>\n")

    def write_footer(self) -> None:
        page_links = [f'<a href="#{i}">{i}</a>' for i in range(1, self.pageno)]
        s = (
            '<div style="position:absolute; top:0px;">'
            f"Page: {', '.join(page_links)}</div>\n"
        )
        self.write(s)
        self.write("</body></html>\n")

    def write_text(self, text: str) -> None:
        self.write(enc(text))

    def place_rect(
        self,
        color: str,
        borderwidth: int,
        x: float,
        y: float,
        w: float,
        h: float,
    ) -> None:
        color2 = self.rect_colors.get(color)
        if color2 is not None:
            s = (
                '<span style="position:absolute; '
                f"border: {color2} {borderwidth}px solid; "
                f"left:{x * self.scale}px; "
                f"top:{(self._yoffset - y) * self.scale}px; "
                f"width:{w * self.scale}px; "
                f'height:{h * self.scale}px;"></span>\n'
            )
            self.write(s)

    def place_border(self, color: str, borderwidth: int, item: LTComponent) -> None:
        self.place_rect(color, borderwidth, item.x0, item.y1, item.width, item.height)

    def place_image(
        self,
        item: LTImage,
        borderwidth: int,
        x: float,
        y: float,
        w: float,
        h: float,
    ) -> None:
        if self.imagewriter is not None:
            name = self.imagewriter.export_image(item)
            s = (
                f'<img src="{enc(name)}" border="{borderwidth}" '
                'style="position:absolute; '
                f"left:{x * self.scale}px; "
                f'top:{(self._yoffset - y) * self.scale}px;" '
                f'width="{w * self.scale}" '
                f'height="{h * self.scale}" />\n'
            )
            self.write(s)

    def place_text(
        self,
        color: str,
        text: str,
        x: float,
        y: float,
        size: float,
    ) -> None:
        color2 = self.text_colors.get(color)
        if color2 is not None:
            s = (
                '<span style="position:absolute; '
                f"color:{color2}; "
                f"left:{x * self.scale}px; "
                f"top:{(self._yoffset - y) * self.scale}px; "
                f'font-size:{size * self.scale * self.fontscale}px;">'
            )
            self.write(s)
            self.write_text(text)
            self.write("</span>\n")

    def begin_div(
        self,
        color: str,
        borderwidth: int,
        x: float,
        y: float,
        w: float,
        h: float,
        writing_mode: str = "False",
    ) -> None:
        self._fontstack.append(self._font)
        self._font = None
        s = (
            '<div style="position:absolute; '
            f"border: {color} {borderwidth}px solid; "
            f"writing-mode:{writing_mode}; "
            f"left:{x * self.scale}px; "
            f"top:{(self._yoffset - y) * self.scale}px; "
            f"width:{w * self.scale}px; "
            f'height:{h * self.scale}px;">'
        )
        self.write(s)

    def end_div(self, color: str) -> None:
        if self._font is not None:
            self.write("</span>")
        self._font = self._fontstack.pop()
        self.write("</div>")

    def put_text(self, text: str, fontname: str, fontsize: float) -> None:
        font = (fontname, fontsize)
        if font != self._font:
            if self._font is not None:
                self.write("</span>")
            # Remove subset tag from fontname, see PDF Reference 5.5.3
            fontname_without_subset_tag = fontname.split("+")[-1]
            self.write(
                '<span style="'
                f"font-family: {fontname_without_subset_tag}; "
                f'font-size:{fontsize * self.scale * self.fontscale}px">'
            )
            self._font = font
        self.write_text(text)

    def put_newline(self) -> None:
        self.write("<br>")

    def receive_layout(self, ltpage: LTPage) -> None:
        def show_group(item: LTTextGroup | TextGroupElement) -> None:
            if isinstance(item, LTTextGroup):
                self.place_border("textgroup", 1, item)
                for child in item:
                    show_group(child)

        def render(item: LTItem) -> None:
            child: LTItem
            if isinstance(item, LTPage):
                self._yoffset += item.y1
                self.place_border("page", 1, item)
                if self.showpageno:
                    self.write(
                        '<div style="position:absolute; top:%dpx;">'
                        f"{(self._yoffset - item.y1) * self.scale}",
                    )
                    self.write(
                        f'<a name="{item.pageid}">Page {item.pageid}</a></div>\n',
                    )
                for child in item:
                    render(child)
                if item.groups is not None:
                    for group in item.groups:
                        show_group(group)
            elif isinstance(item, LTCurve):
                self.place_border("curve", 1, item)
            elif isinstance(item, LTFigure):
                self.begin_div("figure", 1, item.x0, item.y1, item.width, item.height)
                for child in item:
                    render(child)
                self.end_div("figure")
            elif isinstance(item, LTImage):
                self.place_image(item, 1, item.x0, item.y1, item.width, item.height)
            elif self.layoutmode == "exact":
                if isinstance(item, LTTextLine):
                    self.place_border("textline", 1, item)
                    for child in item:
                        render(child)
                elif isinstance(item, LTTextBox):
                    self.place_border("textbox", 1, item)
                    self.place_text(
                        "textbox",
                        str(item.index + 1),
                        item.x0,
                        item.y1,
                        20,
                    )
                    for child in item:
                        render(child)
                elif isinstance(item, LTChar):
                    self.place_border("char", 1, item)
                    self.place_text(
                        "char",
                        item.get_text(),
                        item.x0,
                        item.y1,
                        item.size,
                    )
            elif isinstance(item, LTTextLine):
                for child in item:
                    render(child)
                if self.layoutmode != "loose":
                    self.put_newline()
            elif isinstance(item, LTTextBox):
                self.begin_div(
                    "textbox",
                    1,
                    item.x0,
                    item.y1,
                    item.width,
                    item.height,
                    item.get_writing_mode(),
                )
                for child in item:
                    render(child)
                self.end_div("textbox")
            elif isinstance(item, LTChar):
                fontname = make_compat_str(item.fontname)
                self.put_text(item.get_text(), fontname, item.size)
            elif isinstance(item, LTText):
                self.write_text(item.get_text())

        render(ltpage)
        self._yoffset += self.pagemargin

    def close(self) -> None:
        self.write_footer()


class XMLConverter(PDFConverter[AnyIO]):
    CONTROL = re.compile("[\x00-\x08\x0b-\x0c\x0e-\x1f]")

    def __init__(
        self,
        rsrcmgr: PDFResourceManager,
        outfp: AnyIO,
        codec: str = "utf-8",
        pageno: int = 1,
        laparams: LAParams | None = None,
        imagewriter: ImageWriter | None = None,
        stripcontrol: bool = False,
    ) -> None:
        PDFConverter.__init__(
            self,
            rsrcmgr,
            outfp,
            codec=codec,
            pageno=pageno,
            laparams=laparams,
        )

        # write() assumes a codec for binary I/O, or no codec for text I/O.
        if self.outfp_binary == (not self.codec):
            raise PDFValueError("Codec is required for a binary I/O output")

        self.imagewriter = imagewriter
        self.stripcontrol = stripcontrol
        self.write_header()

    def write(self, text: str) -> None:
        if self.codec:
            cast(BinaryIO, self.outfp).write(text.encode(self.codec))
        else:
            cast(TextIO, self.outfp).write(text)

    def write_header(self) -> None:
        if self.codec:
            self.write(f'<?xml version="1.0" encoding="{self.codec}" ?>\n')
        else:
            self.write('<?xml version="1.0" ?>\n')
        self.write("<pages>\n")

    def write_footer(self) -> None:
        self.write("</pages>\n")

    def write_text(self, text: str) -> None:
        if self.stripcontrol:
            text = self.CONTROL.sub("", text)
        self.write(enc(text))

    def receive_layout(self, ltpage: LTPage) -> None:
        def show_group(item: LTItem) -> None:
            if isinstance(item, LTTextBox):
                self.write(
                    f'<textbox id="{item.index}" bbox="{bbox2str(item.bbox)}" />\n'
                )
            elif isinstance(item, LTTextGroup):
                self.write(f'<textgroup bbox="{bbox2str(item.bbox)}">\n')
                for child in item:
                    show_group(child)
                self.write("</textgroup>\n")

        def render(item: LTItem) -> None:
            child: LTItem
            if isinstance(item, LTPage):
                s = (
                    f'<page id="{item.pageid}" '
                    f'bbox="{bbox2str(item.bbox)}" '
                    f'rotate="{item.rotate}">\n'
                )
                self.write(s)
                for child in item:
                    render(child)
                if item.groups is not None:
                    self.write("<layout>\n")
                    for group in item.groups:
                        show_group(group)
                    self.write("</layout>\n")
                self.write("</page>\n")
            elif isinstance(item, LTLine):
                s = (
                    f"<line "
                    f'linewidth="{item.linewidth}" '
                    f'bbox="{bbox2str(item.bbox)}" />\n'
                )
                self.write(s)
            elif isinstance(item, LTRect):
                s = (
                    f"<rect "
                    f'linewidth="{item.linewidth}" '
                    f'bbox="{bbox2str(item.bbox)}" />\n'
                )
                self.write(s)
            elif isinstance(item, LTCurve):
                s = (
                    f"<curve "
                    f'linewidth="{item.linewidth}" '
                    f'bbox="{bbox2str(item.bbox)}" '
                    f'pts="{item.get_pts()}"/>\n'
                )
                self.write(s)
            elif isinstance(item, LTFigure):
                s = f'<figure name="{item.name}" bbox="{bbox2str(item.bbox)}">\n'
                self.write(s)
                for child in item:
                    render(child)
                self.write("</figure>\n")
            elif isinstance(item, LTTextLine):
                self.write(f'<textline bbox="{bbox2str(item.bbox)}">\n')
                for child in item:
                    render(child)
                self.write("</textline>\n")
            elif isinstance(item, LTTextBox):
                wmode = ""
                if isinstance(item, LTTextBoxVertical):
                    wmode = ' wmode="vertical"'
                s = f'<textbox id="{item.index}" bbox="{bbox2str(item.bbox)}"{wmode}>\n'
                self.write(s)
                for child in item:
                    render(child)
                self.write("</textbox>\n")
            elif isinstance(item, LTChar):
                s = (
                    f"<text "
                    f'font="{enc(item.fontname)}" '
                    f'bbox="{bbox2str(item.bbox)}" '
                    f'colourspace="{item.ncs.name}" '
                    f'ncolour="{item.graphicstate.ncolor}" '
                    f'size="{item.size:.3f}">'
                )
                self.write(s)
                self.write_text(item.get_text())
                self.write("</text>\n")
            elif isinstance(item, LTText):
                self.write(f"<text>{item.get_text()}</text>\n")
            elif isinstance(item, LTImage):
                if self.imagewriter is not None:
                    name = self.imagewriter.export_image(item)
                    self.write(
                        f"<image "
                        f'src="{enc(name)}" '
                        f'width="{item.width}" '
                        f'height="{item.height}" />\n'
                    )
                else:
                    self.write(
                        f'<image width="{item.width}" height="{item.height}" />\n'
                    )
            else:
                raise AssertionError(str(("Unhandled", item)))

        render(ltpage)

    def close(self) -> None:
        self.write_footer()


class HOCRConverter(PDFConverter[AnyIO]):
    """Extract an hOCR representation from explicit text information within a PDF."""

    #   Where text is being extracted from a variety of types of PDF within a
    #   business process, those PDFs where the text is only present in image
    #   form will need to be analysed using an OCR tool which will typically
    #   output hOCR. This converter extracts the explicit text information from
    #   those PDFs that do have it and uses it to genxerate a basic hOCR
    #   representation that is designed to be used in conjunction with the image
    #   of the PDF in the same way as genuine OCR output would be, but without the
    #   inevitable OCR errors.

    #   The converter does not handle images, diagrams or text colors.

    #   In the examples processed by the contributor it was necessary to set
    #   LAParams.all_texts to True.

    CONTROL = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f]")

    def __init__(
        self,
        rsrcmgr: PDFResourceManager,
        outfp: AnyIO,
        codec: str = "utf8",
        pageno: int = 1,
        laparams: LAParams | None = None,
        stripcontrol: bool = False,
    ):
        PDFConverter.__init__(
            self,
            rsrcmgr,
            outfp,
            codec=codec,
            pageno=pageno,
            laparams=laparams,
        )
        self.stripcontrol = stripcontrol
        self.within_chars = False
        self.write_header()

    def bbox_repr(self, bbox: Rect) -> str:
        (in_x0, in_y0, in_x1, in_y1) = bbox
        # PDF y-coordinates are the other way round from hOCR coordinates
        out_x0 = int(in_x0)
        out_y0 = int(self.page_bbox[3] - in_y1)
        out_x1 = int(in_x1)
        out_y1 = int(self.page_bbox[3] - in_y0)
        return f"bbox {out_x0} {out_y0} {out_x1} {out_y1}"

    def write(self, text: str) -> None:
        if self.codec:
            encoded_text = text.encode(self.codec)
            cast(BinaryIO, self.outfp).write(encoded_text)
        else:
            cast(TextIO, self.outfp).write(text)

    def write_header(self) -> None:
        if self.codec:
            self.write(
                "<html xmlns='http://www.w3.org/1999/xhtml' "
                f"xml:lang='en' lang='en' charset='{self.codec}'>\n",
            )
        else:
            self.write(
                "<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>\n",
            )
        self.write("<head>\n")
        self.write("<title></title>\n")
        self.write(
            "<meta http-equiv='Content-Type' content='text/html;charset=utf-8' />\n",
        )
        self.write(
            "<meta name='ocr-system' content='pdfminer.six HOCR Converter' />\n",
        )
        self.write(
            "  <meta name='ocr-capabilities'"
            " content='ocr_page ocr_block ocr_line ocrx_word'/>\n",
        )
        self.write("</head>\n")
        self.write("<body>\n")

    def write_footer(self) -> None:
        self.write("<!-- comment in the following line to debug -->\n")
        self.write(
            "<!--script src='https://unpkg.com/hocrjs'></script--></body></html>\n",
        )

    def write_text(self, text: str) -> None:
        if self.stripcontrol:
            text = self.CONTROL.sub("", text)
        self.write(text)

    def write_word(self) -> None:
        if len(self.working_text) > 0:
            bold_and_italic_styles = ""
            if "Italic" in self.working_font:
                bold_and_italic_styles = "font-style: italic; "
            if "Bold" in self.working_font:
                bold_and_italic_styles += "font-weight: bold; "
            self.write(
                f'<span style=\'font:"{self.working_font}"; '
                f"font-size:{self.working_size}; "
                f"{bold_and_italic_styles}' "
                f"class='ocrx_word' "
                f"title='{self.bbox_repr(self.working_bbox)}; "
                f"x_font {self.working_font}; "
                f"x_fsize {self.working_size}'>"
                f"{self.working_text.strip()}</span>"
            )
        self.within_chars = False

    def receive_layout(self, ltpage: LTPage) -> None:
        def render(item: LTItem) -> None:
            if self.within_chars and isinstance(item, LTAnno):
                self.write_word()
            if isinstance(item, LTPage):
                self.page_bbox = item.bbox
                self.write(
                    f"<div "
                    f"class='ocr_page' "
                    f"id='{item.pageid}' "
                    f"title='{self.bbox_repr(item.bbox)}'>\n",
                )
                for child in item:
                    render(child)
                self.write("</div>\n")
            elif isinstance(item, LTTextLine):
                self.write(
                    f"<span class='ocr_line' title='{self.bbox_repr(item.bbox)}'>",
                )
                for child_line in item:
                    render(child_line)
                self.write("</span>\n")
            elif isinstance(item, LTTextBox):
                self.write(
                    f"<div "
                    f"class='ocr_block' "
                    f"id='{item.index}' "
                    f"title='{self.bbox_repr(item.bbox)}'>\n"
                )
                for child in item:
                    render(child)
                self.write("</div>\n")
            elif isinstance(item, LTChar):
                if not self.within_chars:
                    self.within_chars = True
                    self.working_text = item.get_text()
                    self.working_bbox = item.bbox
                    self.working_font = item.fontname
                    self.working_size = item.size
                elif len(item.get_text().strip()) == 0:
                    self.write_word()
                    self.write(item.get_text())
                else:
                    if (
                        self.working_bbox[1] != item.bbox[1]
                        or self.working_font != item.fontname
                        or self.working_size != item.size
                    ):
                        self.write_word()
                        self.working_bbox = item.bbox
                        self.working_font = item.fontname
                        self.working_size = item.size
                    self.working_text += item.get_text()
                    self.working_bbox = (
                        self.working_bbox[0],
                        self.working_bbox[1],
                        item.bbox[2],
                        self.working_bbox[3],
                    )

        render(ltpage)

    def close(self) -> None:
        self.write_footer()
