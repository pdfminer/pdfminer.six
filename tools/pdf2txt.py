#!/usr/bin/env python

"""
Converts PDF text content (though not images containing text) to plain text, html, xml or "tags".
"""
import argparse
import logging
import six
import sys
import pdfminer.settings
pdfminer.settings.STRICT = False
import pdfminer.high_level
import pdfminer.layout
from pdfminer.image import ImageWriter


def extract_text(files=[], outfile='-',
            _py2_no_more_posargs=None,  # Bloody Python2 needs a shim
            no_laparams=False, all_texts=None, detect_vertical=None, # LAParams
            word_margin=None, char_margin=None, line_margin=None, boxes_flow=None, # LAParams
            output_type='text', codec='utf-8', strip_control=False,
            maxpages=0, page_numbers=None, password="", scale=1.0, rotation=0,
            layoutmode='normal', output_dir=None, debug=False,
            disable_caching=False, **other):
    if _py2_no_more_posargs is not None:
        raise ValueError("Too many positional arguments passed.")
    if not files:
        raise ValueError("Must provide files to work upon!")

    # If any LAParams group arguments were passed, create an LAParams object and
    # populate with given args. Otherwise, set it to None.
    if not no_laparams:
        laparams = pdfminer.layout.LAParams()
        for param in ("all_texts", "detect_vertical", "word_margin", "char_margin", "line_margin", "boxes_flow"):
            paramv = locals().get(param, None)
            if paramv is not None:
                setattr(laparams, param, paramv)
    else:
        laparams = None

    imagewriter = None
    if output_dir:
        imagewriter = ImageWriter(output_dir)

    if output_type == "text" and outfile != "-":
        for override, alttype in (  (".htm", "html"),
                                    (".html", "html"),
                                    (".xml", "xml"),
                                    (".tag", "tag") ):
            if outfile.endswith(override):
                output_type = alttype

    if outfile == "-":
        outfp = sys.stdout
        if outfp.encoding is not None:
            codec = 'utf-8'
    else:
        outfp = open(outfile, "wb")


    for fname in files:
        with open(fname, "rb") as fp:
            pdfminer.high_level.extract_text_to_fp(fp, **locals())
    return outfp


def maketheparser():
    parser = argparse.ArgumentParser(description=__doc__, add_help=True)
    parser.add_argument("files", type=str, default=None, nargs="+", help="File to process.")
    parser.add_argument("-d", "--debug", default=False, action="store_true", help="Debug output.")
    parser.add_argument("-p", "--pagenos", type=str, help="Comma-separated list of page numbers to parse. Included for legacy applications, use --page-numbers for more idiomatic argument entry.")
    parser.add_argument("--page-numbers", type=int, default=None, nargs="+", help="Alternative to --pagenos with space-separated numbers; supercedes --pagenos where it is used.")
    parser.add_argument("-m", "--maxpages", type=int, default=0, help="Maximum pages to parse")
    parser.add_argument("-P", "--password", type=str, default="", help="Decryption password for PDF")
    parser.add_argument("-o", "--outfile", type=str, default="-", help="Output file (default \"-\" is stdout)")
    parser.add_argument("-t", "--output_type", type=str, default="text", help="Output type: text|html|xml|tag (default is text)")
    parser.add_argument("-c", "--codec", type=str, default="utf-8", help="Text encoding")
    parser.add_argument("-s", "--scale", type=float, default=1.0, help="Scale")
    parser.add_argument("-A", "--all-texts", default=None, action="store_true", help="LAParams all texts")
    parser.add_argument("-V", "--detect-vertical", default=None, action="store_true", help="LAParams detect vertical")
    parser.add_argument("-W", "--word-margin", type=float, default=None, help="LAParams word margin")
    parser.add_argument("-M", "--char-margin", type=float, default=None, help="LAParams char margin")
    parser.add_argument("-L", "--line-margin", type=float, default=None, help="LAParams line margin")
    parser.add_argument("-F", "--boxes-flow", type=float, default=None, help="LAParams boxes flow")
    parser.add_argument("-Y", "--layoutmode", default="normal", type=str, help="HTML Layout Mode")
    parser.add_argument("-n", "--no-laparams", default=False, action="store_true", help="Pass None as LAParams")
    parser.add_argument("-R", "--rotation", default=0, type=int, help="Rotation")
    parser.add_argument("-O", "--output-dir", default=None, help="Output directory for images")
    parser.add_argument("-C", "--disable-caching", default=False, action="store_true", help="Disable caching")
    parser.add_argument("-S", "--strip-control", default=False, action="store_true", help="Strip control in XML mode")
    return parser


# main


def main(args=None):

    P = maketheparser()
    A = P.parse_args(args=args)

    if A.page_numbers:
        A.page_numbers = set([x-1 for x in A.page_numbers])
    if A.pagenos:
        A.page_numbers = set([int(x)-1 for x in A.pagenos.split(",")])

    imagewriter = None
    if A.output_dir:
        imagewriter = ImageWriter(A.output_dir)

    if six.PY2 and sys.stdin.encoding:
        A.password = A.password.decode(sys.stdin.encoding)

    if A.output_type == "text" and A.outfile != "-":
        for override, alttype in (  (".htm",  "html"),
                                    (".html", "html"),
                                    (".xml",  "xml" ),
                                    (".tag",  "tag" ) ):
            if A.outfile.endswith(override):
                A.output_type = alttype

    if A.outfile == "-":
        outfp = sys.stdout
        if outfp.encoding is not None:
            # Why ignore outfp.encoding? :-/ stupid cathal?
            A.codec = 'utf-8'
    else:
        outfp = open(A.outfile, "wb")

    ## Test Code
    outfp = extract_text(**vars(A))
    outfp.close()
    return 0


if __name__ == '__main__': sys.exit(main())
