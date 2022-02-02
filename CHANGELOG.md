# Changelog
All notable changes in pdfminer.six will be documented in this file. 

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Export type annotations from pypi package per PEP561 ([#679](https://github.com/pdfminer/pdfminer.six/pull/679))
- Support for identity cmap's ([#626](https://github.com/pdfminer/pdfminer.six/pull/626))
- Add support for PDF page labels ([#680](https://github.com/pdfminer/pdfminer.six/pull/680))

### Fixed
- Hande decompression error due to CRC checksum error ([#637](https://github.com/pdfminer/pdfminer.six/pull/637))
- Regression (since 20191107) in `LTLayoutContainer.group_textboxes` that returned some text lines out of order ([#659](https://github.com/pdfminer/pdfminer.six/pull/659))
- Add handling of JPXDecode filter to enable extraction of images for some pdfs ([#645](https://github.com/pdfminer/pdfminer.six/pull/645))
- Fix extraction of jbig2 files, which was producing invalid files ([#652](https://github.com/pdfminer/pdfminer.six/pull/653))
- Crash in `pdf2txt.py --boxes-flow=disabled` ([#682](https://github.com/pdfminer/pdfminer.six/pull/682))
- Only use xref fallback if `PDFNoValidXRef` is raised and `fallback` is True ([#684](https://github.com/pdfminer/pdfminer.six/pull/684))

### Changed
- Replace warnings.warn with logging.Logger.warning in line with [recommended use](https://docs.python.org/3/howto/logging.html#when-to-use-logging) ([#673](https://github.com/pdfminer/pdfminer.six/pull/673))

### Removed
- Unnecessary return statements without argument at the end of functions ([#707](https://github.com/pdfminer/pdfminer.six/pull/707))

### Changed
- Switched from nose to pytest, from tox to nox and from Travis CI to GitHub Actions ([#704](https://github.com/pdfminer/pdfminer.six/pull/704))

## [20211012]

### Added
- Add support for PDF 2.0 (ISO 32000-2) AES-256 encryption ([#614](https://github.com/pdfminer/pdfminer.six/pull/614))
- Support for Paeth PNG filter compression (predictor value = 4) ([#537](https://github.com/pdfminer/pdfminer.six/pull/537))
- Type annotations ([#661](https://github.com/pdfminer/pdfminer.six/pull/661))

### Fixed
- `KeyError` when `'Encrypt'` but not `'ID'` present in `trailer` ([#594](https://github.com/pdfminer/pdfminer.six/pull/594))
- Fix issue of ValueError and KeyError rasied in PDFdocument and PDFparser ([#573](https://github.com/pdfminer/pdfminer.six/pull/574))
- Fix issue of TypeError: cannot unpack non-iterable PDFObjRef object, when unpacking the value of 'DW2' ([#529](https://github.com/pdfminer/pdfminer.six/pull/529))
- Fix `PermissionError` when creating temporary filepaths on windows when running tests ([#484](https://github.com/pdfminer/pdfminer.six/pull/484))
- Fix `AttributeError` when dumping a TOC with bytes destinations ([#600](https://github.com/pdfminer/pdfminer.six/pull/600))
- Fix issue of some Chinese characters can not be extracted correctly ([#593](https://github.com/pdfminer/pdfminer.six/pull/593))
- Detecting trailer correctly when surrounded with needless whitespace ([#535](https://github.com/pdfminer/pdfminer.six/pull/535))
- Fix `.paint_path` logic for handling single line segments and extracting point-on-curve positions of Beziér path commands ([#530](https://github.com/pdfminer/pdfminer.six/pull/530))
- Raising `UnboundLocalError` when a bad `--output-type`  is used ([#610](https://github.com/pdfminer/pdfminer.six/pull/610))
- `TypeError` when using `TagExtractor` with non-string or non-bytes tag values ([#610](https://github.com/pdfminer/pdfminer.six/pull/610))
- Using `io.TextIOBase` as the file to write to ([#616](https://github.com/pdfminer/pdfminer.six/pull/616))
- Parsing \r\n after the escape character in a literal string ([#616](https://github.com/pdfminer/pdfminer.six/pull/616))

## Removed
- Support for Python 3.4 and 3.5 ([#522](https://github.com/pdfminer/pdfminer.six/pull/522))
- Unused dependency on `sortedcontainers` package ([#525](https://github.com/pdfminer/pdfminer.six/pull/525))
- Support for non-standard output streams that are not binary ([#523](https://github.com/pdfminer/pdfminer.six/pull/523))
- Dependency on typing-extensions introduced by [#661](https://github.com/pdfminer/pdfminer.six/pull/661) ([#677](https://github.com/pdfminer/pdfminer.six/pull/677))

## [20201018]

### Deprecated
- Support for Python 3.4 and 3.5 ([#507](https://github.com/pdfminer/pdfminer.six/pull/507))

### Added

- Option to disable boxes flow layout analysis when using pdf2txt ([#479](https://github.com/pdfminer/pdfminer.six/pull/479))
- Support for `pathlib.PurePath` in `open_filename` ([#492](https://github.com/pdfminer/pdfminer.six/pull/492))

### Fixed
- Pass caching parameter to PDFResourceManager in `high_level` functions ([#475](https://github.com/pdfminer/pdfminer.six/pull/475))
- Fix `.paint_path` logic for handling non-rect quadrilaterals and decomposing complex paths ([#512](https://github.com/pdfminer/pdfminer.six/pull/512))
- Fix out-of-bound access on some PDFs ([#483](https://github.com/pdfminer/pdfminer.six/pull/483))

### Removed
- Remove unused rijndael encryption implementation ([#465](https://github.com/pdfminer/pdfminer.six/pull/465))

## [20200726]

### Fixed
- Rename PDFTextExtractionNotAllowedError to PDFTextExtractionNotAllowed to revert breaking change ([#461](https://github.com/pdfminer/pdfminer.six/pull/461))
- Always try to get CMap, not only for identity encodings ([#438](https://github.com/pdfminer/pdfminer.six/pull/438))

## [20200720]

### Added
- Support for painting multiple rectangles at once ([#371](https://github.com/pdfminer/pdfminer.six/pull/371))

### Fixed
- Validate image object in do_EI is a PDFStream ([#451](https://github.com/pdfminer/pdfminer.six/pull/451))

### Changed
- Hiding fallback xref by default from dumppdf.py output ([#431](https://github.com/pdfminer/pdfminer.six/pull/431))
- Raise a warning instead of an error when extracting text from a non-extractable PDF ([#453](https://github.com/pdfminer/pdfminer.six/pull/453))
- Switched from pycryptodome to cryptography package for AES decryption ([#456](https://github.com/pdfminer/pdfminer.six/pull/456))
  
## [20200517]

### Added
- Python3 shebang line to script in tools ([#408](https://github.com/pdfminer/pdfminer.six/pull/408))

### Fixed
- Fix ordering of textlines within a textbox when `boxes_flow=None` ([#412](https://github.com/pdfminer/pdfminer.six/pull/412))

## [20200402]

### Added
- Allow boxes_flow LAParam to be passed as None, validate the input, and update documentation ([#396](https://github.com/pdfminer/pdfminer.six/pull/396))
- Also accept file-like objects in high level functions `extract_text` and `extract_pages` ([#393](https://github.com/pdfminer/pdfminer.six/pull/393))

### Fixed
- Text no longer comes in reverse order when advanced layout analysis is disabled ([#399](https://github.com/pdfminer/pdfminer.six/pull/399))
- Updated misleading documentation for `word_margin` and `char_margin` ([#407](https://github.com/pdfminer/pdfminer.six/pull/407))
- Ignore ValueError when converting font encoding differences ([#389](https://github.com/pdfminer/pdfminer.six/pull/389))
- Grouping of text lines outside of parent container bounding box ([#386](https://github.com/pdfminer/pdfminer.six/pull/386))

### Changed
- Group text lines if they are centered ([#384](https://github.com/pdfminer/pdfminer.six/pull/384))

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
- Files for external applications such as django, cgi and pyinstaller ([#320](https://github.com/pdfminer/pdfminer.six/pull/320))

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
