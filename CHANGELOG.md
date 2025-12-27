# Changelog
All notable changes in pdfminer.six will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security

- **CRITICAL**: Eliminated arbitrary code execution vulnerability (CVE-2025-64512) by completely removing pickle support for CMap storage - users with custom pickle CMaps can use `tools/convert_cmaps_to_json.py` to convert to JSON format ([GHSA-wf5f-4jwr-ppcp](https://github.com/pdfminer/pdfminer.six/security/advisories/GHSA-wf5f-4jwr-ppcp))

### Fixed

- `IndexError` when saving image with no filters`` ([#1117](https://github.com/pdfminer/pdfminer.six/pull/1135))
- Copying color space scs and ncs ([#1140](https://github.com/pdfminer/pdfminer.six/pull/1140))

## [20251107]

### Fixed

- Arbitrary code execution when loading pickle cmaps ([issue](https://github.com/pdfminer/pdfminer.six/security/advisories/GHSA-wf5f-4jwr-ppcp))

## [20250506]

## Added

- Support for extracting images with TIFF predictor ([#1058](https://github.com/pdfminer/pdfminer.six/pull/1058))

## Fixed

- Correct tightest fitting bounding boxes for rotated content ([#1114](https://github.com/pdfminer/pdfminer.six/pull/1114))
- `TypeError` when passing wrong number of arguments to `safe_rgb` ([#1118](https://github.com/pdfminer/pdfminer.six/pull/1118))
- `OverflowError` in `safe_float` when input is too large ([#1121](https://github.com/pdfminer/pdfminer.six/pull/1121))
- Saving colour spaces on the graphics stack ([#1119](https://github.com/pdfminer/pdfminer.six/pull/1119))
- Remove padding from AES-encrypted strings([#1123](https://github.com/pdfminer/pdfminer.six/pull/1123))

## [20250416]

### Fixed

- `TypeError` when parsing font width with indirect object references ([#1098](https://github.com/pdfminer/pdfminer.six/pull/1098))
- `ValueError` when loading xref with invalid position or generation numbers that cannot be parsed as int ([#1099](https://github.com/pdfminer/pdfminer.six/pull/1099))
- Safely converting PDF stack objects to float or int in PDFInterpreter ([#1100](https://github.com/pdfminer/pdfminer.six/pull/1100))
- `TypeError` when parsing font bbox with incorrect values ([#1103](https://github.com/pdfminer/pdfminer.six/pull/1103))
- `ValueError` on incorrect stream lengths for ASCII85 data ([#1112](https://github.com/pdfminer/pdfminer.six/pull/1112))

## [20250327]

### Added

- Support for Python 3.13 ([#1092](https://github.com/pdfminer/pdfminer.six/pull/1092))

### Changed

- Reduce memory overhead on runlength encoding by using lists ([#1055](https://github.com/pdfminer/pdfminer.six/pull/1055))
- Using `pyproject.toml` instead of `setup.py` ([#1028](https://github.com/pdfminer/pdfminer.six/pull/1028))

### Fixed

- `TypeError` when CID character widths are not parseable as floats ([#1001](https://github.com/pdfminer/pdfminer.six/pull/1001))
- `TypeError` raised by extract_text method with compressed PDF file ([#1029](https://github.com/pdfminer/pdfminer.six/pull/1029))
- `PSBaseParser` can't handle tokens split across end of buffer ([#1030](https://github.com/pdfminer/pdfminer.six/pull/1030))
- `TypeError` when CropBox is an indirect object reference ([#1004](https://github.com/pdfminer/pdfminer.six/issues/1004))
- Remove redundant line to be able to recognize rectangles ([#1066](https://github.com/pdfminer/pdfminer.six/pull/1066))
- Support indirect objects for filters ([#1062](https://github.com/pdfminer/pdfminer.six/pull/1068))
- Make sure `bytes` is `bytes` where it counts ([#1069](https://github.com/pdfminer/pdfminer.six/pull/1069))

### Removed

- Support for Python 3.8 ([#1091](https://github.com/pdfminer/pdfminer.six/pull/1091))

## [20250324]

### Changed

- Using absolute instead of relative imports ([[#995](https://github.com/pdfminer/pdfminer.six/pull/995)])
- Using standard library functions for ascii85 and asciihex ([#1031](https://github.com/pdfminer/pdfminer.six/pull/1031))

### Deprecated

- The third argument (generation number) to `PDFObjRef` ([#972](https://github.com/pdfminer/pdfminer.six/pull/972))

### Fixed

- `TypeError` when corrupt PDF object reference cannot be parsed as int ([#972](https://github.com/pdfminer/pdfminer.six/pull/972))])
- `TypeError` when corrupt PDF literal cannot be converted to str ([#978](https://github.com/pdfminer/pdfminer.six/pull/978))
- `ValueError` when corrupt PDF specifies a negative xref location ([#980](http://github.com/pdfminer/pdfminer.six/pull/980))
- `ValueError` when corrupt PDF specifies an invalid mediabox ([#987](https://github.com/pdfminer/pdfminer.six/pull/987))
- `RecursionError` when corrupt PDF specifies a recursive /Pages object ([#998](https://github.com/pdfminer/pdfminer.six/pull/998))
- `TypeError` when corrupt PDF specifies text-positioning operators with invalid values ([#1000](https://github.com/pdfminer/pdfminer.six/pull/1000))
- inline image parsing fails when stream data contains "EI\n" ([#1008](https://github.com/pdfminer/pdfminer.six/issues/1008
- `TypeError` when parsing object reference as mediabox ([#1082](https://github.com/pdfminer/pdfminer.six/issues/1082))

### Removed

- Deprecated tools, functions and classes ([#974](https://github.com/pdfminer/pdfminer.six/pull/974))

## [20240706]

### Added

- Support for zipped jpeg's ([#938](https://github.com/pdfminer/pdfminer.six/pull/938))
- Fuzzing harnesses for integration into Google's OSS-Fuzz ([949](https://github.com/pdfminer/pdfminer.six/pull/949))
- Support for setuptools-git-versioning version 2.0.0 ([#957](https://github.com/pdfminer/pdfminer.six/pull/957))

### Fixed

- Resolving mediabox and pdffont ([#834](https://github.com/pdfminer/pdfminer.six/pull/834))
- Keywords that aren't terminated by the pattern `END_KEYWORD` before end-of-stream are parsed ([#885](https://github.com/pdfminer/pdfminer.six/pull/885))
- `ValueError` wrong error message when specifying codec for text output  ([#902](https://github.com/pdfminer/pdfminer.six/pull/902))
- Resolve stream filter parameters ([#906](https://github.com/pdfminer/pdfminer.six/pull/906))
- Reading cmap's with whitespace in the name ([#935](https://github.com/pdfminer/pdfminer.six/pull/935))
- Optimize `apply_png_predictor` by using lists ([#912](https://github.com/pdfminer/pdfminer.six/pull/912))

### Changed

- Updated Python 3.7 syntax to 3.8 ([#956](https://github.com/pdfminer/pdfminer.six/pull/956))
- Updated all Python version specifications to a minimum of 3.8 ([#969](https://github.com/pdfminer/pdfminer.six/pull/969))

## [20231228]

### Removed
- Support for Python 3.6 and 3.7 ([#921](https://github.com/pdfminer/pdfminer.six/pull/921))

### Added

- Output converter for the hOCR format ([#651](https://github.com/pdfminer/pdfminer.six/pull/651))
- Font name aliases for Arial, Courier New and Times New Roman ([#790](https://github.com/pdfminer/pdfminer.six/pull/790))
- Documentation on why special characters can sometimes not be extracted ([#829](https://github.com/pdfminer/pdfminer.six/pull/829))
- Storing Bezier path and dashing style of line in LTCurve ([#801](https://github.com/pdfminer/pdfminer.six/pull/801))

### Fixed

- Broken CI/CD pipeline by setting upper version limit for black, mypy, pip and setuptools ([#921](https://github.com/pdfminer/pdfminer.six/pull/921))
- `flake8` failures ([#921](https://github.com/pdfminer/pdfminer.six/pull/921))
- `ValueError` when bmp images with 1 bit channel are decoded ([#773](https://github.com/pdfminer/pdfminer.six/issues/773))
- `ValueError` when trying to decrypt empty metadata values ([#766](https://github.com/pdfminer/pdfminer.six/issues/766))
- Sphinx errors during building of documentation ([#760](https://github.com/pdfminer/pdfminer.six/pull/760))
- `TypeError` when getting default width of font ([#720](https://github.com/pdfminer/pdfminer.six/issues/720))
- Installing typing-extensions on Python 3.6 and 3.7 ([#775](https://github.com/pdfminer/pdfminer.six/pull/775))
- `TypeError` in cmapdb.py when parsing null characters ([#768](https://github.com/pdfminer/pdfminer.six/pull/768))
- Color "convenience operators" now (per spec) also set color space ([#794](https://github.com/pdfminer/pdfminer.six/pull/794))
- `ValueError` when extracting images, due to breaking changes in Pillow ([#827](https://github.com/pdfminer/pdfminer.six/pull/827))
- Small typo's and issues in the documentation ([#828](https://github.com/pdfminer/pdfminer.six/pull/828))
- Ignore non-Unicode cmaps in TrueType fonts ([#806](https://github.com/pdfminer/pdfminer.six/pull/806))

### Changed

- Using non-hardcoded version string and setuptools-git-versioning to enable installation from source and building on Python 3.12 ([#922](https://github.com/pdfminer/pdfminer.six/issues/922))

### Deprecated

- Usage of `if __name__ == "__main__"` where it was only intended for testing purposes ([#756](https://github.com/pdfminer/pdfminer.six/pull/756))

### Removed

- Support for Python 3.6 and 3.7 because they are end-of-life ([#923](https://github.com/pdfminer/pdfminer.six/pull/923))

## [20220524]

### Fixed

- Ignoring (invalid) path constructors that do not begin with `m` ([#749](https://github.com/pdfminer/pdfminer.six/pull/749))

### Changed

- Removed upper version bounds ([#755](https://github.com/pdfminer/pdfminer.six/pull/755))

## [20220506]

### Fixed

- `IndexError` when handling invalid bfrange code map in
  CMap ([#731](https://github.com/pdfminer/pdfminer.six/pull/731))
- `TypeError` in lzw.py when `self.table` is not set ([#732](https://github.com/pdfminer/pdfminer.six/pull/732))
- `TypeError` in encodingdb.py when name of unicode is not
  str ([#733](https://github.com/pdfminer/pdfminer.six/pull/733))
- `TypeError` in HTMLConverter when using a bytes fontname ([#734](https://github.com/pdfminer/pdfminer.six/pull/734))

### Added

- Exporting images without any specific encoding ([#737](https://github.com/pdfminer/pdfminer.six/pull/737))

### Changed

- Using charset-normalizer instead of chardet for less restrictive license ([#744](https://github.com/pdfminer/pdfminer.six/pull/744))

## [20220319]

### Added

- Export type annotations from pypi package per PEP561 ([#679](https://github.com/pdfminer/pdfminer.six/pull/679))
- Support for identity cmap's ([#626](https://github.com/pdfminer/pdfminer.six/pull/626))
- Add support for PDF page labels ([#680](https://github.com/pdfminer/pdfminer.six/pull/680))
- Installation of Pillow as an optional extra dependency ([#714](https://github.com/pdfminer/pdfminer.six/pull/714))

### Fixed

- Hande decompression error due to CRC checksum error ([#637](https://github.com/pdfminer/pdfminer.six/pull/637))
- Regression (since 20191107) in `LTLayoutContainer.group_textboxes` that returned some text lines out of order ([#659](https://github.com/pdfminer/pdfminer.six/pull/659))
- Add handling of JPXDecode filter to enable extraction of images for some pdfs ([#645](https://github.com/pdfminer/pdfminer.six/pull/645))
- Fix extraction of jbig2 files, which was producing invalid files ([#652](https://github.com/pdfminer/pdfminer.six/pull/653))
- Crash in `pdf2txt.py --boxes-flow=disabled` ([#682](https://github.com/pdfminer/pdfminer.six/pull/682))
- Only use xref fallback if `PDFNoValidXRef` is raised and `fallback` is True ([#684](https://github.com/pdfminer/pdfminer.six/pull/684))
- Ignore empty characters when analyzing layout ([#499](https://github.com/pdfminer/pdfminer.six/pull/499))

### Changed
- Replace warnings.warn with logging.Logger.warning in line with [recommended use](https://docs.python.org/3/howto/logging.html#when-to-use-logging) ([#673](https://github.com/pdfminer/pdfminer.six/pull/673))
- Switched from nose to pytest, from tox to nox and from Travis CI to GitHub Actions ([#704](https://github.com/pdfminer/pdfminer.six/pull/704))

### Removed
- Unnecessary return statements without argument at the end of functions ([#707](https://github.com/pdfminer/pdfminer.six/pull/707))

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

### Removed
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

## [20200124]

### Security
- Removed samples/issue-00152-embedded-pdf.pdf because it contains a possible security thread; a javascript enabled object ([#364](https://github.com/pdfminer/pdfminer.six/pull/364))

## [20200121]

### Fixed
- Interpret two's complement integer as unsigned integer ([#352](https://github.com/pdfminer/pdfminer.six/pull/352))
- Fix font name in html output such that it is recognized by browser ([#357](https://github.com/pdfminer/pdfminer.six/pull/357))
- Compute correct font height by removing scaling with font bounding box height ([#348](https://github.com/pdfminer/pdfminer.six/pull/348))
- KeyError when extracting embedded files and a Unicode file specification is missing ([#338](https://github.com/pdfminer/pdfminer.six/pull/338))

### Removed
- The command-line utility latin2ascii.py ([#360](https://github.com/pdfminer/pdfminer.six/pull/360))

## [20200104]

### Removed
- Support for Python 2 ([#346](https://github.com/pdfminer/pdfminer.six/pull/346))

### Changed
- Enforce pep8 coding style by adding flake8 to CI ([#345](https://github.com/pdfminer/pdfminer.six/pull/345))

## [20191110]

### Fixed
- Wrong order of text box grouping introduced by PR #315 ([#335](https://github.com/pdfminer/pdfminer.six/pull/335))

## [20191107]

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

## [20191020]

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

## [20181108]

### Changed
- Speedup layout analysis ([#141](https://github.com/pdfminer/pdfminer.six/pull/141))
- Use argparse instead of replace deprecated getopt ([#173](https://github.com/pdfminer/pdfminer.six/pull/173))
- Allow pdfminer.six to be compiled with cython ([#142](https://github.com/pdfminer/pdfminer.six/pull/142))
