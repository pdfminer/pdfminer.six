
from .psparser import LIT

import six #Python 2+3 compatibility

##  PDFColorSpace
##
LITERAL_DEVICE_GRAY = LIT('DeviceGray')
LITERAL_DEVICE_RGB = LIT('DeviceRGB')
LITERAL_DEVICE_CMYK = LIT('DeviceCMYK')


class PDFColorSpace(object):

    def __init__(self, name, ncomponents):
        self.name = name
        self.ncomponents = ncomponents
        return

    def __repr__(self):
        return '<PDFColorSpace: %s, ncomponents=%d>' % (self.name, self.ncomponents)


PREDEFINED_COLORSPACE = {}
for (name, n) in six.iteritems({
    'CalRGB': 3,
    'CalGray': 1,
    'Lab': 3,
    'DeviceRGB': 3,
    'DeviceCMYK': 4,
    'DeviceGray': 1,
    'Separation': 1,
    'Indexed': 1,
    'Pattern': 1,
}) :
    PREDEFINED_COLORSPACE[name]=PDFColorSpace(name, n)
    