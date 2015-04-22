import math
import os
from struct import pack, unpack, calcsize

# segment header literals

HEADER_FLAG_DEFERRED = 0b10000000
HEADER_FLAG_PAGE_ASSOC_LONG = 0b01000000

SEG_TYPE_MASK = 0b00111111

REF_COUNT_SHORT_MASK = 0b11100000
REF_COUNT_LONG_MASK = 0x1fffffff
REF_COUNT_LONG = 7

DATA_LEN_UNKNOWN = 0xffffffff

# segment types

SEG_TYPE_IMMEDIATE_GEN_REGION = 38

def bit_set(bit_pos, value):
    return bool((value >> bit_pos) & 1)

def check_flag(flag, value):
    return bool(flag & value)

def masked_value(mask, value):
    for bit_pos in range(0, 31):
        if bit_set(bit_pos, mask):
            return (value & mask) >> bit_pos

    raise Exception("Invalid mask or value")

class JBIG2StreamReader(object):
    fields = [
        (">L", "number"),
        (">B", "flags"),
        (">B", "retention_flags"),
        (">B", "page_assoc"),
        (">L", "data_length"),
    ]

    def __init__(self, stream):
        self.stream = stream

    def get_segments(self):
        segments = []
        while not self.is_eof():
            segment = {}
            for field_format, name in self.fields:
                field_len = calcsize(field_format)
                field = self.stream.read(field_len)
                if len(field) < field_len:
                    segment["_error"] = True
                    break
                value = unpack(field_format, field)
                if len(value) == 1:
                    [value] = value
                parser = getattr(self, "parse_%s" % name, None)
                if callable(parser):
                    value = parser(segment, value, field)
                segment[name] = value

            if not segment.get("_error"):
                segments.append(segment)
        return segments

    def is_eof(self):
        if self.stream.read(1) == '':
            return True
        else:
            self.stream.seek(-1, os.SEEK_CUR)
            return False

    def parse_flags(self, segment, flags, field):
        return {
            "deferred": check_flag(HEADER_FLAG_DEFERRED, flags),
            "page_assoc_long": check_flag(HEADER_FLAG_PAGE_ASSOC_LONG, flags),
            "type": masked_value(SEG_TYPE_MASK, flags)
        }

    def parse_retention_flags(self, segment, flags, field):
        ref_count = masked_value(REF_COUNT_SHORT_MASK, flags)
        retain_segments = []
        ref_segments = []

        if ref_count < REF_COUNT_LONG:
            for bit_pos in range(5):
                retain_segments.append(bit_set(bit_pos, flags))
        else:
            field += self.stream.read(3)
            [ref_count] = unpack(">L", field)
            ref_count = masked_value(REF_COUNT_LONG_MASK, ref_count)
            ret_bytes_count = int(ceil((ref_count+1)/8))
            for ret_byte_index in range(ret_bytes_count):
                [ret_byte] = unpack(">B", self.stream.read(1))
                for bit_pos in range(7):
                    retain_segments.append(bit_set(bit_pos, ret_byte))

        seg_num = segment["number"]
        if seg_num <= 256:
            ref_format = ">B"
        elif seg_num <= 65536:
            ref_format = ">I"
        else:
            ref_format = ">L"

        ref_size = calcsize(ref_format)

        for ref_index in range(ref_count):
            ref = stream.read(ref_size)
            [ref] = unpack(ref_format, ref)
            ref_segments.append(ref)

        return {
            "ref_count": ref_count,
            "retain_segments": retain_segments,
            "ref_segments": ref_segments,
        }

    def parse_page_assoc(self, segment, page, field):
        if segment["flags"]["page_assoc_long"]:
            field += self.stream.read(3)
            [page] = unpack(">L", field)
        return page

    def parse_data_length(self, segment, length, field):
        if length:
            if (segment["flags"]["type"] == SEG_TYPE_IMMEDIATE_GEN_REGION)\
                and (length == DATA_LEN_UNKNOWN):

                raise NotImplementedError(
                    "Working with unknown segment length "
                    "is not implemented yet"
                )
            else:
                segment["data"] = self.stream.read(length)

        return length
