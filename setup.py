from setuptools import setup
import sys
import os
import pdfminer as package

requires = ['six', 'pycryptodome', 'sortedcontainers']
if sys.version_info >= (3, 0):
    requires.append('chardet')

thisDir = os.path.abspath(os.path.dirname(__file__))

CMAPSRC = os.path.join(thisDir, "cmaprsrc")
CMAPDST = os.path.join(thisDir, "pdfminer", "cmap")
cid2codeFileName="cid2code.txt"
from tools.conv_cmap import do_conversion
charmapConversionTargets=[
    {
        "enc2codec":{"B5":"cp950", "UniCNS-UTF8":"utf-8"},
        "args":[os.path.join(CMAPSRC, "Adobe-CNS1-7", cid2codeFileName)],
        "regname": "Adobe-CNS1"
    },
    {
        "enc2codec":{"GBK-EUC":"cp936", "UniGB":"utf-8"},
        "args":[os.path.join(CMAPSRC, "Adobe-GB1-5", cid2codeFileName)],
        "regname":"Adobe-GB1"
    },
    {
        "enc2codec":{"RKSJ":"cp932", "EUC":"euc-jp", "UniJIS-UTF8":"utf-8"},
        "args":[os.path.join(CMAPSRC, "Adobe-Japan1-7", cid2codeFileName)],
        "regname":"Adobe-Japan1"
    },
    {
        "enc2codec":{"KSC-EUC":"euc-kr", "KSC-Johab":"johab", "KSCms-UHC":"cp949", "UniKS-UTF8":"utf-8"},
        "args":[os.path.join(CMAPSRC, "Adobe-Korea1-2", cid2codeFileName)],
        "regname":"Adobe-Korea1"
    }
]
for cmTarget in charmapConversionTargets:
    do_conversion(outdir=CMAPDST, **cmTarget)

setup(
    name='pdfminer.six',
    version=package.__version__,
    packages=['pdfminer'],
    package_data={'pdfminer': ['cmap/*.pickle.gz']},
    install_requires=requires,
    description='PDF parser and analyzer',
    long_description=package.__doc__,
    license='MIT/X',
    author='Yusuke Shinyama + Philippe Guglielmetti',
    author_email='pdfminer@goulu.net',
    url='https://github.com/pdfminer/pdfminer.six',
    scripts=[
        'tools/pdf2txt.py',
        'tools/dumppdf.py',
        'tools/latin2ascii.py',
    ],
    keywords=[
        'pdf parser',
        'pdf converter',
        'layout analysis',
        'text mining',
    ],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Topic :: Text Processing',
    ],
)
