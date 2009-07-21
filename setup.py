#!/usr/bin/env python
from distutils.core import setup
from pdfminer import __version__

setup(
  name='pdfminer',
  version=__version__,
  description='PDF parser and analyzer',
  long_description='''PDFMiner is a suite of programs that help
extracting and analyzing text data of PDF documents.
Unlike other PDF-related tools, it allows to obtain
the exact location of texts in a page, as well as 
other extra information such as font information or ruled lines.
It includes a PDF converter that can transform PDF files
into other text formats (such as HTML). It has an extensible
PDF parser that can be used for other purposes instead of text analysis.''',
  keywords=['pdf parser', 'pdf converter', 'text mining'],
  license='MIT/X',
  author='Yusuke Shinyama',
  author_email='yusuke at cs dot nyu dot edu',
  url='http://www.unixuser.org/~euske/python/pdfminer/index.html',
  packages=['pdfminer'],
  scripts=['tools/pdf2txt.py', 'tools/dumppdf.py'],
  classifiers=[
  'Development Status :: 4 - Beta',
  'Environment :: Console',
  'Intended Audience :: Developers',
  'Intended Audience :: Science/Research',
  'License :: OSI Approved :: MIT License',
  ],
  )
