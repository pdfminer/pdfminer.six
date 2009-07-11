#!/usr/bin/env python
from distutils.core import setup
from pdfminer import __version__

setup(name='pdfminer',
      version=__version__,
      description='PDF parser and analyzer',
      license='MIT/X',
      author='Yusuke Shinyama',
      url='http://www.unixuser.org/~euske/python/pdfminer/index.html',
      packages=['pdfminer'],
      scripts=['tools/pdf2txt.py', 'tools/dumppdf.py'],
      )
