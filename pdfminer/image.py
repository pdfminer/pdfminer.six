#!/usr/bin/env python
import struct
import os
import os.path
from io import BytesIO
from .pdftypes import LITERALS_DCT_DECODE
from .pdfcolor import LITERAL_DEVICE_GRAY
from .pdfcolor import LITERAL_DEVICE_RGB
from .pdfcolor import LITERAL_DEVICE_CMYK


def align32(x):
    return ((x+3)//4)*4


##  BMPWriter
##
class BMPWriter(object):

    def __init__(self, fp, bits, width, height):
        self.fp = fp
        self.bits = bits
        self.width = width
        self.height = height
        if bits == 1:
            ncols = 2
        elif bits == 8:
            ncols = 256
        elif bits == 24:
            ncols = 0
        else:
            raise ValueError(bits)
        self.linesize = align32((self.width*self.bits+7)//8)
        self.datasize = self.linesize * self.height
        headersize = 14+40+ncols*4
        info = struct.pack('<IiiHHIIIIII', 40, self.width, self.height, 1, self.bits, 0, self.datasize, 0, 0, ncols, 0)
        assert len(info) == 40, len(info)
        header = struct.pack('<ccIHHI', b'B', b'M', headersize+self.datasize, 0, 0, headersize)
        assert len(header) == 14, len(header)
        self.fp.write(header)
        self.fp.write(info)
        if ncols == 2:
            # B&W color table
            for i in (0, 255):
                self.fp.write(struct.pack('BBBx', i, i, i))
        elif ncols == 256:
            # grayscale color table
            for i in xrange(256):
                self.fp.write(struct.pack('BBBx', i, i, i))
        self.pos0 = self.fp.tell()
        self.pos1 = self.pos0 + self.datasize
        return

    def write_line(self, y, data):
        self.fp.seek(self.pos1 - (y+1)*self.linesize)
        self.fp.write(data)
        return


##  ImageWriter
##
class ImageWriter(object):

    def __init__(self, outdir):
        self.outdir = outdir
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)
        return

    def export_image(self, image):
        stream = image.stream
        filters = stream.get_filters()
        (width, height) = image.srcsize
        if len(filters) == 1 and filters[0][0] in LITERALS_DCT_DECODE:
            ext = '.jpg'
        elif (image.bits == 1 or
              image.bits == 8 and image.colorspace in (LITERAL_DEVICE_RGB, LITERAL_DEVICE_GRAY)):
            ext = '.%dx%d.bmp' % (width, height)
        else:
            ext = '.%d.%dx%d.img' % (image.bits, width, height)
        name = image.name+ext
        path = os.path.join(self.outdir, name)
        fp = file(path, 'wb')
        if ext == '.jpg':
            raw_data = stream.get_rawdata()
            if LITERAL_DEVICE_CMYK in image.colorspace:
                from PIL import Image
                from PIL import ImageChops
                ifp = BytesIO(raw_data)
                i = Image.open(ifp)
                i = ImageChops.invert(i)
                i = i.convert('RGB')
                i.save(fp, 'JPEG')
            else:
                fp.write(raw_data)
        elif image.bits == 1:
            bmp = BMPWriter(fp, 1, width, height)
            data = stream.get_data()
            i = 0
            width = (width+7)//8
            for y in xrange(height):
                bmp.write_line(y, data[i:i+width])
                i += width
        elif image.bits == 8 and image.colorspace is LITERAL_DEVICE_RGB:
            bmp = BMPWriter(fp, 24, width, height)
            data = stream.get_data()
            i = 0
            width = width*3
            for y in xrange(height):
                bmp.write_line(y, data[i:i+width])
                i += width
        elif image.bits == 8 and image.colorspace is LITERAL_DEVICE_GRAY:
            bmp = BMPWriter(fp, 8, width, height)
            data = stream.get_data()
            i = 0
            for y in xrange(height):
                bmp.write_line(y, data[i:i+width])
                i += width
        else:
            fp.write(stream.get_data())
        fp.close()
        return name
