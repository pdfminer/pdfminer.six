"""
Fork of PDFMiner using six for Python 2+3 compatibility

PDFMiner is a tool for extracting information from PDF documents.
Unlike other PDF-related tools, it focuses entirely on getting and analyzing
text data. PDFMiner allows to obtain the exact location of texts in a page,
as well as other information such as fonts or lines.
It includes a PDF converter that can transform PDF files into other text
formats (such as HTML). It has an extensible PDF parser that can be used for
other purposes instead of text analysis.
"""
__version__ = '20181108'

if __name__ == '__main__':
    print(__version__)
