# Changelog
All notable changes in pdfminer.six will be documented in this file. 

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [20200402]

### Added
- Allow boxes_flow LAParam to be passed as None, validate the input, and update documentation ([#395](https://github.com/pdfminer/pdfminer.six/pull/395))

### Fixed
- Text no longer comes in reverse order when advanced layout analysis is disabled ([#398](https://github.com/pdfminer/pdfminer.six/pull/398))
- Updated misleading documentation for `word_margin` and `char_margin` ([#407](https://github.com/pdfminer/pdfminer.six/pull/407))
- Ignore ValueError when converting font encoding differences ([#389](https://github.com/pdfminer/pdfminer.six/pull/389))
- Grouping of text lines outside of parent container bounding box ([#386](https://github.com/pdfminer/pdfminer.six/pull/386))

### Added
- Also accept file-like objects in high level functions `extract_text` and `extract_pages` ([#392](https://github.com/pdfminer/pdfminer.six/pull/392))

### Changed
- Group text lines if they are centered ([#382](https://github.com/pdfminer/pdfminer.six/pull/382))

## [20200124] - 2020-01-24

### Security
- Removed samples/issue-00152-embedded-pdf.pdf because it contains a possible security thread; a javascript enabled object ([#364](https://github.com/pdfminer/pdfminer.six/pull/364))

## [20200121] - 2020-01-21

### Fixed
- Interpret two's complement integer as unsigned integer ([#352](https://github.com/pdfminer/pdfminer.six/pull/352))
- Fix font name in html output such that it is recognized by browser ([#357](https://github.com/pdfminer/pdfminer.six/pull/357))
- Compute correct font height by removing scaling with font bounding box height ([#348](https://github.com/pdfminer/pdfminer.six/pull/348))
- KeyError when extracting embedded files and a Unicode file specification is missing ([#338](https://github.com/pdfminer/pdfminer.six/pull/338))

### Removed
- The command-line utility latin2ascii.py ([#360](https://github.com/pdfminer/pdfminer.six/pull/360))

## [20200104] - 2019-01-04

## Removed
- Support for Python 2 ([#346](https://github.com/pdfminer/pdfminer.six/pull/346))

### Changed
- Enforce pep8 coding style by adding flake8 to CI ([#345](https://github.com/pdfminer/pdfminer.six/pull/345))

## [20191110] - 2019-11-10

### Fixed
- Wrong order of text box grouping introduced by PR #315 ([#335](https://github.com/pdfminer/pdfminer.six/pull/335))

## [20191107] - 2019-11-07

### Deprecated
- The argument `_py2_no_more_posargs` because Python2 is removed on January
, 2020 ([#328](https://github.com/pdfminer/pdfminer.six/pull/328) and 
[#307](https://github.com/pdfminer/pdfminer.six/pull/307))

### Added
- Simple wrapper to easily extract text from a PDF file [#330](https://github.com/pdfminer/pdfminer.six/pull/330)
- Support for extracting JBIG2 encoded images ([#311](https://github.com/pdfminer/pdfminer.six/pull/311) and [#46](https://github.com/pdfminer/pdfminer.six/pull/46))
- Sphinx documentation that is published on 
  [Read the Docs](https://pdfminersix.readthedocs.io/)
  ([#329](https://github.com/pdfminer/pdfminer.six/pull/329))

### Fixed
- Unhandled AssertionError when dumping pdf containing reference to object id 0 
 ([#318](https://github.com/pdfminer/pdfminer.six/pull/318))
- Debug flag actually changes logging level to debug for pdf2txt.py and
 dumppdf.py ([#325](https://github.com/pdfminer/pdfminer.six/pull/325))

### Changed
- Using argparse instead of getopt for command line interface of dumppdf.py ([#321](https://github.com/pdfminer/pdfminer.six/pull/321))
- Refactor `LTLayoutContainer.group_textboxes` for a significant speed up in layout analysis ([#315](https://github.com/pdfminer/pdfminer.six/pull/315))

### Removed
- Files for external applications such as django, cgi and pyinstaller ([#314](https://github.com/pdfminer/pdfminer.six/issues/314))

## [20191020] - 2019-10-20

### Deprecated
- Support for Python 2 is dropped at January 1st, 2020 ([#307](https://github.com/pdfminer/pdfminer.six/pull/307))

### Added
- Contribution guidelines in [CONTRIBUTING.md](CONTRIBUTING.md) ([#259](https://github.com/pdfminer/pdfminer.six/pull/259))
- Support new encodings OneByteEncoding and DLIdent for CMaps ([#283](https://github.com/pdfminer/pdfminer.six/pull/283))

### Fixed
- Use `six.iteritems()` instead of `dict().iteritems()` to ensure Python2 and Python3 compatibility ([#274](https://github.com/pdfminer/pdfminer.six/pull/274))
- Properly convert Adobe Glyph names to unicode characters ([#263](https://github.com/pdfminer/pdfminer.six/pull/263))
- Allow CMap to be a content stream ([#283](https://github.com/pdfminer/pdfminer.six/pull/283))
- Resolve indirect objects for width and bounding boxes for fonts ([#273](https://github.com/pdfminer/pdfminer.six/pull/273))
- Actually updating stroke color in graphic state ([#298](https://github.com/pdfminer/pdfminer.six/pull/298))
- Interpret (invalid) negative font descent as a positive descent ([#203](https://github.com/pdfminer/pdfminer.six/pull/203))
- Correct colorspace comparision for images ([#132](https://github.com/pdfminer/pdfminer.six/pull/132))
- Allow for bounding boxes with zero height or width by removing assertion ([#246](https://github.com/pdfminer/pdfminer.six/pull/246))

### Changed
- All dependencies are managed in `setup.py` ([#306](https://github.com/pdfminer/pdfminer.six/pull/306) and [#219](https://github.com/pdfminer/pdfminer.six/pull/219))

## [20181108] - 2018-11-08

### Changed
- Speedup layout analysis ([#141](https://github.com/pdfminer/pdfminer.six/pull/141))
- Use argparse instead of replace deprecated getopt ([#173](https://github.com/pdfminer/pdfminer.six/pull/173))
- Allow pdfminer.six to be compiled with cython ([#142](https://github.com/pdfminer/pdfminer.six/pull/142))
