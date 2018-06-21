#!/usr/bin/env python

"""
compares rwo pdf files.
"""
import sys
import logging
import six
import pdfminer.settings
pdfminer.settings.STRICT = False
import pdfminer.high_level
import pdfminer.layout

def compare(file1,file2,**args):
    if args.get('_py2_no_more_posargs',None) is not None:
        raise ValueError("Too many positional arguments passed.")


    # If any LAParams group arguments were passed, create an LAParams object and
    # populate with given args. Otherwise, set it to None.
    if args.get('laparams',None) is None:
        laparams = pdfminer.layout.LAParams()
        for param in ("all_texts", "detect_vertical", "word_margin", "char_margin", "line_margin", "boxes_flow"):
            paramv = args.get(param, None)
            if paramv is not None:
                laparams[param]=paramv
        args['laparams']=laparams
                
    s1=six.StringIO()
    with open(file1, "rb") as fp:
        pdfminer.high_level.extract_text_to_fp(fp,s1, **args)
    
    s2=six.StringIO()
    with open(file2, "rb") as fp:
        pdfminer.high_level.extract_text_to_fp(fp,s2, **args)
    
    import difflib
    s1.seek(0)
    s2.seek(0)
    s1,s2=s1.readlines(), s2.readlines()
    
    import os.path
    try:
        extension = os.path.splitext(args['outfile'])[1][1:4]
        if extension.lower()=='htm':
            return difflib.HtmlDiff().make_file(s1,s2)
    except KeyError:
        pass
    return difflib.unified_diff(s1,s2,n=args['context_lines'])


# main
def main(args=None):
    import argparse
    P = argparse.ArgumentParser(description=__doc__)
    P.add_argument("file1", type=str, default=None, help="File 1 to compare.")
    P.add_argument("file2", type=str, default=None, help="File 2 to compare.")
    P.add_argument("-o", "--outfile", type=str, default="-", 
        help="Output file (default/'-' is stdout) \
        if .htm or .html, create an HTML table (or a complete HTML file containing the table) \
        showing a side by side, line by line comparison of text with inter-line \
        and intra-line change highlights. \
        The table can be generated in either full or contextual difference mode."
    )
    P.add_argument("-N", "--context-lines", default=3, type=int, help = "context lines shown")
    P.add_argument("-d", "--debug", default=False, action="store_true", help="Debug output.")

    # params for pdf2txt
    P.add_argument("-p", "--pagenos", type=str, help="Comma-separated list of page numbers to parse. Included for legacy applications, use --page-numbers for more idiomatic argument entry.")
    P.add_argument("--page-numbers", type=int, default=None, nargs="+", help="Alternative to --pagenos with space-separated numbers; supercedes --pagenos where it is used.")
    P.add_argument("-m", "--maxpages", type=int, default=0, help = "Maximum pages to parse")
    P.add_argument("-P", "--password", type=str, default="", help = "Decryption password for both PDFs")
    P.add_argument("-t", "--output_type", type=str, default="text", help = "pdf2txt type: text|html|xml|tag (default is text)")
    P.add_argument("-c", "--codec", type=str, default="utf-8", help = "Text encoding")
    P.add_argument("-s", "--scale", type=float, default=1.0, help = "Scale")
    P.add_argument("-A", "--all-texts", default=None, action="store_true", help="LAParams all texts")
    P.add_argument("-V", "--detect-vertical", default=None, action="store_true", help="LAParams detect vertical")
    P.add_argument("-W", "--word-margin", type=float, default=None, help = "LAParams word margin")
    P.add_argument("-M", "--char-margin", type=float, default=None, help = "LAParams char margin")
    P.add_argument("-L", "--line-margin", type=float, default=None, help = "LAParams line margin")
    P.add_argument("-F", "--boxes-flow", type=float, default=None, help = "LAParams boxes flow")
    P.add_argument("-Y", "--layoutmode", default="normal", type=str, help="HTML Layout Mode")
    P.add_argument("-n", "--no-laparams", default=False, action="store_true", help = "Pass None as LAParams")
    P.add_argument("-R", "--rotation", default=0, type=int, help = "Rotation")
    P.add_argument("-O", "--output-dir", default=None, help="Output directory for images")
    P.add_argument("-C", "--disable-caching", default=False, action="store_true", help="Disable caching")
    P.add_argument("-S", "--strip-control", default=False, action="store_true", help="Strip control in XML mode")
    

    A = P.parse_args(args=args)

    if A.page_numbers:
        A.page_numbers = set([x-1 for x in A.page_numbers])
    if A.pagenos:
        A.page_numbers = set([int(x)-1 for x in A.pagenos.split(",")])

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
    else:
        outfp = open(A.outfile, "w", encoding='utf-8')
    outfp.writelines(compare(**vars(A)))
    outfp.close()
    return 0


if __name__ == '__main__': sys.exit(main())
