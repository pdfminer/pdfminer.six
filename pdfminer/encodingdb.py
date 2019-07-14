
import re

import six  # Python 2+3 compatibility

from .glyphlist import glyphname2unicode
from .latin_enc import ENCODING
from .psparser import PSLiteral

HEXADECIMAL = re.compile(r'[0-9a-fA-F]+')


def name2unicode(name):
    """Converts Adobe glyph names to Unicode numbers.

    In contrast to the specification, this raises a KeyError instead of return an empty string when the key is unknown.
    This way the caller must explicitly define what to do when there is not a match.

    Reference: https://github.com/adobe-type-tools/agl-specification#2-the-mapping

    :returns unicode character if name resembles something, otherwise a KeyError
    """
    full_stop = u'\u002E'
    name = name.split(full_stop)[0]
    components = name.split('_')

    if len(components) > 1:
        return ''.join(map(name2unicode, components))

    else:
        if name in glyphname2unicode:
            return glyphname2unicode.get(name)

        elif name.startswith('uni'):
            name_without_uni = name.strip('uni')
            if HEXADECIMAL.match(name_without_uni) and len(name_without_uni) % 4 == 0:
                unicode_digits = [int(name_without_uni[i:i + 4], base=16) for i in range(0, len(name_without_uni), 4)]
                if any([55295 < digit < 57344 for digit in unicode_digits]):
                    raise KeyError
                characters = map(six.unichr, unicode_digits)
                return ''.join(characters)

        elif name.startswith('u'):
            name_without_u = name.strip('u')
            if HEXADECIMAL.match(name_without_u) and 4 <= len(name_without_u) <= 6:
                unicode_digit = int(name_without_u, base=16)
                if 55295 < unicode_digit < 57344:
                    raise KeyError
                return six.unichr(unicode_digit)

    raise KeyError


class EncodingDB(object):

    std2unicode = {}
    mac2unicode = {}
    win2unicode = {}
    pdf2unicode = {}
    for (name, std, mac, win, pdf) in ENCODING:
        c = name2unicode(name)
        if std:
            std2unicode[std] = c
        if mac:
            mac2unicode[mac] = c
        if win:
            win2unicode[win] = c
        if pdf:
            pdf2unicode[pdf] = c

    encodings = {
        'StandardEncoding': std2unicode,
        'MacRomanEncoding': mac2unicode,
        'WinAnsiEncoding': win2unicode,
        'PDFDocEncoding': pdf2unicode,
    }

    @classmethod
    def get_encoding(klass, name, diff=None):
        cid2unicode = klass.encodings.get(name, klass.std2unicode)
        if diff:
            cid2unicode = cid2unicode.copy()
            cid = 0
            for x in diff:
                if isinstance(x, int):
                    cid = x
                elif isinstance(x, PSLiteral):
                    try:
                        cid2unicode[cid] = name2unicode(x.name)
                    except KeyError:
                        pass
                    cid += 1
        return cid2unicode
