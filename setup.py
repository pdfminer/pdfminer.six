#!/usr/bin/env python
from distutils.core import setup

setup(name='pdfminer',
      version='20090330',
      description='PDF parser and analyzer',
      license='MIT/X',
      author='Yusuke Shinyama',
      url='http://www.unixuser.org/~euske/python/pdfminer/index.html',
      packages=['pdfminer'],
      scripts=['tools/pdf2txt.py', 'tools/dumppdf.py'],
      )
