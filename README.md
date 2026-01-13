pdfminer.six
============

[![Continuous integration](https://github.com/pdfminer/pdfminer.six/actions/workflows/actions.yml/badge.svg)](https://github.com/pdfminer/pdfminer.six/actions/workflows/actions.yml)
[![PyPI version](https://img.shields.io/pypi/v/pdfminer.six.svg)](https://pypi.python.org/pypi/pdfminer.six/)
[![gitter](https://badges.gitter.im/pdfminer-six/Lobby.svg)](https://gitter.im/pdfminer-six/Lobby?utm_source=badge&utm_medium)

*We fathom PDF*

Pdfminer.six is a community maintained fork of the original PDFMiner. It is a tool for extracting information from PDF
documents. It focuses on getting and analyzing text data. Pdfminer.six extracts the text from a page directly from the
sourcecode of the PDF. It can also be used to get the exact location, font or color of the text.

It is built in a modular way such that each component of pdfminer.six can be replaced easily. You can implement your own
interpreter or rendering device that uses the power of pdfminer.six for other purposes than text analysis.

Check out the full documentation on
[Read the Docs](https://pdfminersix.readthedocs.io).


Features
--------

* Written entirely in Python.
* Parse, analyze, and convert PDF documents.
* Extract content as text, images, html or [hOCR](https://en.wikipedia.org/wiki/HOCR).
* Support for PDF-1.7 specification (well, almost).
* Support for CJK languages and vertical writing.
* Support for various font types (Type1, TrueType, Type3, and CID) support.
* Support for extracting embedded images (JPG, PNG, TIFF, JBIG2, bitmaps).
* Support for decoding various compressions (ASCIIHexDecode, ASCII85Decode, LZWDecode, FlateDecode, RunLengthDecode,
  CCITTFaxDecode)
* Support for RC4 and AES encryption.
* Support for AcroForm interactive form extraction.
* Table of contents extraction.
* Tagged contents extraction.
* Automatic layout analysis.
* **Performance optimized** with O(n) parsing algorithms and comprehensive benchmarking.

How to use
----------

* Install Python 3.10 or newer.
* Install pdfminer.six.
  ```bash
  pip install pdfminer.six

* (Optionally) install extra dependencies for extracting images.

  ```bash
  pip install 'pdfminer.six[image]'

* Use the command-line interface to extract text from pdf.

  ```bash
  pdf2txt.py example.pdf

* Or use it with Python.
  ```python
  from pdfminer.high_level import extract_text

  text = extract_text("example.pdf")
  print(text)
  ```

Performance
-----------

pdfminer.six is optimized for performance with systematic benchmarking:

* **O(n) parsing algorithms** - Eliminated quadratic complexity bottlenecks
* **Comprehensive benchmark suite** - 35+ benchmarks tracking parser performance
* **Real-world metrics** - Extract text from 33KB PDF in ~3.5ms (289 ops/sec)
* **Regression prevention** - Automated performance testing in CI

See [PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md) for detailed metrics and methodology.

Run benchmarks yourself:
```bash
pip install pytest-benchmark
pytest benchmarks/ --benchmark-only
```

Contributing
------------

We welcome contributions! Whether you want to fix a bug, add a feature, or improve documentation, your help is appreciated.

Please note that as a community-maintained project with limited maintainer availability, the best way to get an issue resolved is to submit a pull request yourself.

To get started:
1. Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and coding standards
2. Check out the [open issues](https://github.com/pdfminer/pdfminer.six/issues) to find something to work on
3. Join the discussion on [Gitter](https://gitter.im/pdfminer-six/Lobby) if you have questions

Acknowledgement
---------------

This repository includes code from `pyHanko` ; the original license has been included [here](/docs/licenses/LICENSE.pyHanko).
