#!/usr/bin/python
# -*- coding: utf-8 -*-
import six

import nose, logging, os

if six.PY3:
    from tools import dumppdf
elif six.PY2:
    import os, sys
    sys.path.append(os.path.abspath(os.path.curdir))
    import tools.dumppdf as dumppdf

path=os.path.dirname(os.path.abspath(__file__))+'/'

def run(datapath,filename,options=None):
    i=path+datapath+filename+'.pdf'
    o=path+filename+'.xml'
    if options:
        s='dumppdf -o%s %s %s'%(o,options,i)
    else:
         s='dumppdf -o%s %s'%(o,i)
    dumppdf.main(s.split(' '))

class TestDumpPDF():
    

    def test_1(self):
        run('../samples/','jo','-t -a')
        run('../samples/','simple1','-t -a')
        run('../samples/','simple2','-t -a')
        run('../samples/','simple3','-t -a')
        
    def test_2(self):
        run('../samples/nonfree/','dmca','-t -a')
        
    def test_3(self):
        run('../samples/nonfree/','f1040nr')

    def test_4(self):
        run('../samples/nonfree/','i1040nr')
        
    def test_5(self):
        run('../samples/nonfree/','kampo','-t -a')
        
    def test_6(self):
        run('../samples/nonfree/','naacl06-shinyama','-t -a')

if __name__ == '__main__':
    #import logging,sys,os,six
    #logging.basicConfig(level=logging.DEBUG, filename='%s_%d.%d.log'%(os.path.basename(__file__),sys.version_info[0],sys.version_info[1]))
    nose.runmodule()
