#!/usr/bin/env python3
from pathlib import Path
from setuptools import setup
from setuptools.config import read_configuration
import sys

thisDir=Path(__file__).parent

import pdfminer as package

requires = ['six', 'pycryptodome']
if sys.version_info >= (3, 0):
    requires.append('chardet')

cfg = read_configuration(str(thisDir / 'setup.cfg'))

cfg["metadata"]["version"]=package.__version__
cfg["metadata"]["requires"]=requires
cfg["metadata"]["long_description"]=package.__doc__
cfg["options"]["package_data"]={'pdfminer': ['cmap/*.pickle.gz']}
cfg["options"]["scripts"]=[
    'tools/pdf2txt.py',
    'tools/dumppdf.py',
    'tools/latin2ascii.py',
]
#print(cfg)
cfg["options"].update(cfg["metadata"])
cfg=cfg["options"]

setup(**cfg)
