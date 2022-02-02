import sys
from pathlib import Path

from setuptools import setup
from os import path

sys.path.append(str(Path(__file__).parent))
import pdfminer as package


with open(path.join(path.abspath(path.dirname(__file__)), 'README.md')) as f:
    readme = f.read()

setup(
    name='pdfminer.six',
    version=package.__version__,
    packages=['pdfminer'],
    package_data={'pdfminer': ['cmap/*.pickle.gz', 'py.typed']},
    install_requires=[
        'chardet ; python_version > "3.0"',
        'cryptography',
    ],
    extras_require={
        "dev": ["pytest", "nox", "mypy == 0.931"],
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
    python_requires='>=3.6',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: MIT License',
        'Topic :: Text Processing',
    ],
)
