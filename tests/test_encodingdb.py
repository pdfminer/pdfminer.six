"""Tests based on the Adobe Glyph List Specification
See: https://github.com/adobe-type-tools/agl-specification#2-the-mapping

While not in the specification, lowercase unicode often occurs in pdf's.
Therefore lowercase unittest variants are added.
"""
from nose.tools import assert_raises

from pdfminer.encodingdb import name2unicode, EncodingDB
from pdfminer.psparser import PSLiteral


def test_name2unicode_name_in_agl():
    """The name "Lcommaaccent" has a single component,
    which is mapped to the string U+013B by AGL"""
    assert '\u013B' == name2unicode('Lcommaaccent')


def test_name2unicode_uni():
    """The components "Lcommaaccent," "uni013B," and "u013B"
    all map to the string U+013B"""
    assert '\u013B' == name2unicode('uni013B')


def test_name2unicode_uni_lowercase():
    """The components "Lcommaaccent," "uni013B," and "u013B"
    all map to the string U+013B"""
    assert '\u013B' == name2unicode('uni013b')


def test_name2unicode_uni_with_sequence_of_digits():
    """The name "uni20AC0308" has a single component,
    which is mapped to the string U+20AC U+0308"""
    assert '\u20AC\u0308' == name2unicode('uni20AC0308')


def test_name2unicode_uni_with_sequence_of_digits_lowercase():
    """The name "uni20AC0308" has a single component,
    which is mapped to the string U+20AC U+0308"""
    assert '\u20AC\u0308' == name2unicode('uni20ac0308')


def test_name2unicode_uni_empty_string():
    """The name "uni20ac" has a single component,
    which is mapped to a euro-sign.

    According to the specification this should be mapped to an empty string,
    but we also want to support lowercase hexadecimals"""
    assert '\u20ac' == name2unicode('uni20ac')


def test_name2unicode_uni_empty_string_long():
    """The name "uniD801DC0C" has a single component,
    which is mapped to an empty string

    Neither D801 nor DC0C are in the appropriate set.
    This form cannot be used to map to the character which is
    expressed as D801 DC0C in UTF-16, specifically U+1040C.
    This character can be correctly mapped by using the
    glyph name "u1040C.
    """
    assert_raises(KeyError, name2unicode, 'uniD801DC0C')


def test_name2unicode_uni_empty_string_long_lowercase():
    """The name "uniD801DC0C" has a single component,
    which is mapped to an empty string

    Neither D801 nor DC0C are in the appropriate set.
    This form cannot be used to map to the character which is
    expressed as D801 DC0C in UTF-16, specifically U+1040C.
    This character can be correctly mapped by using the
    glyph name "u1040C."""
    assert_raises(KeyError, name2unicode, 'uniD801DC0C')


def test_name2unicode_uni_pua():
    """"Ogoneksmall" and "uniF6FB" both map to the string that corresponds to
     U+F6FB."""
    assert '\uF6FB' == name2unicode('uniF6FB')


def test_name2unicode_uni_pua_lowercase():
    """"Ogoneksmall" and "uniF6FB" both map to the string that corresponds to
     U+F6FB."""
    assert '\uF6FB' == name2unicode('unif6fb')


def test_name2unicode_u_with_4_digits():
    """The components "Lcommaaccent," "uni013B," and "u013B" all map to the
    string U+013B"""
    assert '\u013B' == name2unicode('u013B')


def test_name2unicode_u_with_4_digits_lowercase():
    """The components "Lcommaaccent," "uni013B," and "u013B" all map to the
    string U+013B"""
    assert '\u013B' == name2unicode('u013b')


def test_name2unicode_u_with_5_digits():
    """The name "u1040C" has a single component, which is mapped to the string
     U+1040C"""
    assert '\U0001040C' == name2unicode('u1040C')


def test_name2unicode_u_with_5_digits_lowercase():
    """The name "u1040C" has a single component, which is mapped to the string
     U+1040C"""
    assert '\U0001040C' == name2unicode('u1040c')


def test_name2unicode_multiple_components():
    """The name "Lcommaaccent_uni20AC0308_u1040C.alternate" is mapped to the
    string U+013B U+20AC U+0308 U+1040C"""
    assert '\u013B\u20AC\u0308\U0001040C' == \
           name2unicode('Lcommaaccent_uni20AC0308_u1040C.alternate')


def test_name2unicode_multiple_components_lowercase():
    """The name "Lcommaaccent_uni20AC0308_u1040C.alternate" is mapped to the
     string U+013B U+20AC U+0308 U+1040C"""
    assert '\u013B\u20AC\u0308\U0001040C' == \
           name2unicode('Lcommaaccent_uni20ac0308_u1040c.alternate')


def test_name2unicode_foo():
    """The name 'foo' maps to an empty string,
    because 'foo' is not in AGL,
    and because it does not start with a 'u.'"""
    assert_raises(KeyError, name2unicode, 'foo')


def test_name2unicode_notdef():
    """The name ".notdef" is reduced to an empty string (step 1)
    and mapped to an empty string (step 3)"""
    assert_raises(KeyError, name2unicode, '.notdef')


def test_name2unicode_pua_ogoneksmall():
    """"
    Ogoneksmall" and "uniF6FB" both map to the string
    that corresponds to U+F6FB."""
    assert '\uF6FB' == name2unicode('Ogoneksmall')


def test_name2unicode_overflow_error():
    assert_raises(KeyError, name2unicode, '226215240241240240240240')


def test_get_encoding_with_invalid_differences():
    """Invalid differences should be silently ignored

    Regression test for https://github.com/pdfminer/pdfminer.six/issues/385
    """
    invalid_differences = [PSLiteral('ubuntu'), PSLiteral('1234')]
    EncodingDB.get_encoding('StandardEncoding', invalid_differences)
