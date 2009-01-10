#!/usr/bin/env python
import sys
stderr = sys.stderr
from pdflib.psparser import PSLiteralTable


##  ColorSpace
##
LITERAL_DEVICE_GRAY = PSLiteralTable.intern('DeviceGray')
LITERAL_DEVICE_RGB = PSLiteralTable.intern('DeviceRGB')
LITERAL_DEVICE_CMYK = PSLiteralTable.intern('DeviceCMYK')

class ColorSpace(object):
  
  def __init__(self, name, ncomponents):
    self.name = name
    self.ncomponents = ncomponents
    return
  
  def __repr__(self):
    return '<ColorSpace: %s, ncomponents=%d>' % (self.name, self.ncomponents)


PREDEFINED_COLORSPACE = dict(
  (name, ColorSpace(name,n)) for (name,n) in {
  'CalRGB': 3,
  'CalGray': 1,
  'Lab': 3,
  'DeviceRGB': 3,
  'DeviceCMYK': 4,
  'DeviceGray': 1,
  'Separation': 1,
  'Indexed': 1,
  'Pattern': 1,
  }.iteritems())
