#!/usr/bin/env python

# -*- coding: utf-8 -*-

import nose, logging, os

import tools.pdf2txt as pdf2txt

path=os.path.dirname(os.path.abspath(__file__))+'/'

def run(datapath,filename,options=None):
    i=path+datapath+filename+'.pdf'
    o=path+filename+'.txt'
    if options:
        s='pdf2txt -o%s %s %s'%(o,options,i)
    else:
         s='pdf2txt -o%s %s'%(o,i)
    pdf2txt.main(s.split(' ')[1:])

class TestDumpPDF():

    def test_1(self):
        run('../samples/','jo')
        run('../samples/','simple1')
        run('../samples/','simple2')
        run('../samples/','simple3')
        run('../samples/','sampleOneByteIdentityEncode')

    def test_2(self):
        run('../samples/nonfree/','dmca')

    def test_3(self):
        run('../samples/nonfree/','f1040nr')

    def test_4(self):
        run('../samples/nonfree/','i1040nr')

    def test_5(self):
        run('../samples/nonfree/','kampo')

    def test_6(self):
        run('../samples/nonfree/','naacl06-shinyama')

    # this test works on Windows but on Linux & Travis-CI it says
    # PDFSyntaxError: No /Root object! - Is this really a PDF?
    # TODO: Find why
    """
    def test_7(self):
        run('../samples/contrib/','stamp-no')
    """

    def test_8(self):
        run('../samples/contrib/','2b','-A -t xml')

    def test_9(self):
        run('../samples/nonfree/','175') # https://github.com/pdfminer/pdfminer.six/issues/65

    def test_10(self):
        run('../samples/scancode/','patchelf') # https://github.com/euske/pdfminer/issues/96

if __name__ == '__main__':
    nose.runmodule()
