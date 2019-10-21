"""
Fork of PDFMiner

PDFMiner is a tool for extracting information from PDF documents.
Unlike other PDF-related tools, it focuses entirely on getting and analyzing
text data. PDFMiner allows to obtain the exact location of texts in a page,
as well as other information such as fonts or lines.
It includes a PDF converter that can transform PDF files into other text
formats (such as HTML). It has an extensible PDF parser that can be used for
other purposes instead of text analysis.
"""
import sys
import warnings

__version__ = '20191020'


if sys.version_info < (3, 0):
    warnings.warn('On January 1st, 2020, pdfminer.six will stop supporting Python 2. Please upgrade to Python 3. For '
                  'more information see https://github.com/pdfminer/pdfminer.six/issues/194')

if __name__ == '__main__':
    print(__version__)
