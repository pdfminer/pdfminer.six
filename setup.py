from setuptools import setup
from os import path

import pdfminer as package


with open(path.join(path.abspath(path.dirname(__file__)), 'README.md')) as f:
    readme = f.read()

setup(
    name='pdfminer.six',
    version=package.__version__,
    packages=['pdfminer'],
    package_data={'pdfminer': ['cmap/*.pickle.gz']},
    install_requires=[
        'chardet ; python_version > "3.0"',
        'pycryptodome',
        'sortedcontainers',
    ],
    extras_require={
        "dev": ["nose", "tox"],
        "docs": ["sphinx", "sphinx-argparse"],
    },
    description='PDF parser and analyzer',
    long_description=readme,
    long_description_content_type='text/markdown',
    license='MIT/X',
    author='Yusuke Shinyama + Philippe Guglielmetti',
    author_email='pdfminer@goulu.net',
    url='https://github.com/pdfminer/pdfminer.six',
    scripts=[
        'tools/pdf2txt.py',
        'tools/dumppdf.py',
    ],
    keywords=[
        'pdf parser',
        'pdf converter',
        'layout analysis',
        'text mining',
    ],
    python_requires='>=3.4',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3 :: Only',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Topic :: Text Processing',
    ],
)
