#!/usr/bin/env python
import logging
from .psparser import LIT
from .pdftypes import PDFObjectNotFound
from .pdftypes import resolve1
from .pdftypes import int_value
from .pdftypes import list_value
from .pdftypes import dict_value
from .pdfparser import PDFParser
from .pdfdocument import PDFDocument
from .pdfdocument import PDFTextExtractionNotAllowed

# some predefined literals and keywords.
LITERAL_PAGE = LIT('Page')
LITERAL_PAGES = LIT('Pages')


##  PDFPage
##
class PDFPage(object):

    """An object that holds the information about a page.

    A PDFPage object is merely a convenience class that has a set
    of keys and values, which describe the properties of a page
    and point to its contents.

    Attributes:
      doc: a PDFDocument object.
      pageid: any Python object that can uniquely identify the page.
      attrs: a dictionary of page attributes.
      contents: a list of PDFStream objects that represents the page content.
      lastmod: the last modified time of the page.
      resources: a list of resources used by the page.
      mediabox: the physical size of the page.
      cropbox: the crop rectangle of the page.
      rotate: the page rotation (in degree).
      annots: the page annotations.
      beads: a chain that represents natural reading order.
    """

    debug = False

    def __init__(self, doc, pageid, attrs):
        """Initialize a page object.

        doc: a PDFDocument object.
        pageid: any Python object that can uniquely identify the page.
        attrs: a dictionary of page attributes.
        """
        self.doc = doc
        self.pageid = pageid
        self.attrs = dict_value(attrs)
        self.lastmod = resolve1(self.attrs.get('LastModified'))
        self.resources = resolve1(self.attrs.get('Resources', dict()))
        self.mediabox = resolve1(self.attrs['MediaBox'])
        if 'CropBox' in self.attrs:
            self.cropbox = resolve1(self.attrs['CropBox'])
        else:
            self.cropbox = self.mediabox
        self.rotate = (int_value(self.attrs.get('Rotate', 0))+360) % 360
        self.annots = self.attrs.get('Annots')
        self.beads = self.attrs.get('B')
        if 'Contents' in self.attrs:
            contents = resolve1(self.attrs['Contents'])
        else:
            contents = []
        if not isinstance(contents, list):
            contents = [contents]
        self.contents = contents
        return

    def __repr__(self):
        return '<PDFPage: Resources=%r, MediaBox=%r>' % (self.resources, self.mediabox)

    INHERITABLE_ATTRS = set(['Resources', 'MediaBox', 'CropBox', 'Rotate'])

    @classmethod
    def create_pages(klass, document):
        def search(obj, parent):
            if isinstance(obj, int):
                objid = obj
                tree = dict_value(document.getobj(objid)).copy()
            else:
                objid = obj.objid
                tree = dict_value(obj).copy()
            for (k, v) in parent.iteritems():
                if k in klass.INHERITABLE_ATTRS and k not in tree:
                    tree[k] = v
            if tree.get('Type') is LITERAL_PAGES and 'Kids' in tree:
                if klass.debug: logging.info('Pages: Kids=%r' % tree['Kids'])
                for c in list_value(tree['Kids']):
                    for x in search(c, tree):
                        yield x
            elif tree.get('Type') is LITERAL_PAGE:
                if klass.debug: logging.info('Page: %r' % tree)
                yield (objid, tree)
        pages = False
        if 'Pages' in document.catalog:
            for (objid, tree) in search(document.catalog['Pages'], document.catalog):
                yield klass(document, objid, tree)
                pages = True
        if not pages:
            # fallback when /Pages is missing.
            for xref in document.xrefs:
                for objid in xref.get_objids():
                    try:
                        obj = document.getobj(objid)
                        if isinstance(obj, dict) and obj.get('Type') is LITERAL_PAGE:
                            yield klass(document, objid, obj)
                    except PDFObjectNotFound:
                        pass
        return

    @classmethod
    def get_pages(klass, fp,
                  pagenos=None, maxpages=0, password=b'',
                  caching=True, check_extractable=True):
        # Create a PDF parser object associated with the file object.
        parser = PDFParser(fp)
        # Create a PDF document object that stores the document structure.
        doc = PDFDocument(parser, password=password, caching=caching)
        # Check if the document allows text extraction. If not, abort.
        if check_extractable and not doc.is_extractable:
            raise PDFTextExtractionNotAllowed('Text extraction is not allowed: %r' % fp)
        # Process each page contained in the document.
        for (pageno, page) in enumerate(klass.create_pages(doc)):
            if pagenos and (pageno not in pagenos):
                continue
            yield page
            if maxpages and maxpages <= pageno+1:
                break
        return
