from setuptools import setup
import sys

import pdfminer as package

requires = ['six', 'pycryptodome', 'pygame']
if sys.version_info >= (3, 0):
    requires.append('chardet')

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
