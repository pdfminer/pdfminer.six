pdfminer.rtl
============


This is a fork of pdfminer.six that attempts to add RTL support with python-bidi. This version is experimental and probably buggy. Please don't rely on it for critical projects.

Check out the full original documentation on
[Read the Docs](https://pdfminersix.readthedocs.io).


Features
--------

* (Added RTL support)
* Written entirely in Python.
* Parse, analyze, and convert PDF documents.
* Extract content as text, images, html or [hOCR](https://en.wikipedia.org/wiki/HOCR).
* PDF-1.7 specification support. (well, almost).
* CJK languages and vertical writing scripts support.
* Various font types (Type1, TrueType, Type3, and CID) support.
* Support for extracting images (JPG, JBIG2, Bitmaps).
* Support for various compressions (ASCIIHexDecode, ASCII85Decode, LZWDecode, FlateDecode, RunLengthDecode,
  CCITTFaxDecode)
* Support for RC4 and AES encryption.
* Support for AcroForm interactive form extraction.
* Table of contents extraction.
* Tagged contents extraction.
* Automatic layout analysis.

How to use
----------

* Install Python 3.8 or newer.
* Install pdfminer.rtl.

  `pip install pdfminer.rtl`

* (Optionally) install extra dependencies for extracting images.

  `pip install 'pdfminer.rtl[image]'`

* Use the command-line interface to extract text from pdf.

  `pdf2txt.py example.pdf`

* Or use it with Python. 

```python
from pdfminer.high_level import extract_text

text = extract_text("example.pdf")
print(text)
```

Acknowledgement
---------------

This repository includes code from `pyHanko` ; the original license has been included [here](/docs/licenses/LICENSE.pyHanko) and to all the other contirbutors of the original project see [here](https://github.com/pdfminer/pdfminer.six/graphs/contributors)
