#!/usr/bin/env python3
import argparse
import codecs
import gzip
import json
import sys
from pathlib import Path
from typing import List, Any


class CMapConverter:
    def __init__(self, enc2codec={}):
        self.enc2codec = enc2codec
        self.code2cid = {}  # {'cmapname': ...}
        self.is_vertical = {}
        self.cid2unichr_h = {}  # {cid: unichr}
        self.cid2unichr_v = {}  # {cid: unichr}
        return

    def get_encs(self):
        return self.code2cid.keys()

    def get_maps(self, enc):
        if enc.endswith("-H"):

            (hmapenc, vmapenc) = (enc, None)
        elif enc == "H":
            (hmapenc, vmapenc) = ("H", "V")
        else:
            (hmapenc, vmapenc) = (enc + "-H", enc + "-V")
        if hmapenc in self.code2cid:
            hmap = self.code2cid[hmapenc]
        else:
            hmap = {}
            self.code2cid[hmapenc] = hmap
        vmap = None
        if vmapenc:
            self.is_vertical[vmapenc] = True
            if vmapenc in self.code2cid:
                vmap = self.code2cid[vmapenc]
            else:
                vmap = {}
                self.code2cid[vmapenc] = vmap
        return (hmap, vmap)

    def load(self, fp):
        encs = None
        for line in fp:
            (line, _, _) = line.strip().partition("#")
            if not line:
                continue
            values = line.split("\t")
            if encs is None:
                assert values[0] == "CID", str(values)
                encs = values
                continue

            def put(dmap, code, cid, force=False):
                for b in code[:-1]:
                    if b in dmap:
                        dmap = dmap[b]
                    else:
                        d = {}
                        dmap[b] = d
                        dmap = d
                b = code[-1]
                if force or ((b not in dmap) or dmap[b] == cid):
                    dmap[b] = cid
                return

            def add(unimap, enc, code):
                try:
                    codec = self.enc2codec[enc]
                    c = code.decode(codec, "strict")
                    if len(c) == 1:
                        if c not in unimap:
                            unimap[c] = 0
                        unimap[c] += 1
                except KeyError:
                    pass
                except UnicodeError:
                    pass
                return

            def pick(unimap):
                chars = list(unimap.items())
                chars.sort(key=(lambda x: (x[1], -ord(x[0]))), reverse=True)
                (c, _) = chars[0]
                return c

            cid = int(values[0])
            unimap_h = {}
            unimap_v = {}
            for (enc, value) in zip(encs, values):
                if enc == "CID":
                    continue
                if value == "*":
                    continue

                # hcodes, vcodes: encoded bytes for each writing mode.
                hcodes = []
                vcodes = []
                for code in value.split(","):
                    vertical = code.endswith("v")
                    if vertical:
                        code = code[:-1]
                    try:
                        code = codecs.decode(code, "hex_codec")
                    except Exception:
                        code = chr(int(code, 16))
                    if vertical:
                        vcodes.append(code)
                        add(unimap_v, enc, code)
                    else:
                        hcodes.append(code)
                        add(unimap_h, enc, code)
                # add cid to each map.
                (hmap, vmap) = self.get_maps(enc)
                if vcodes:
                    assert vmap is not None
                    for code in vcodes:
                        put(vmap, code, cid, True)
                    for code in hcodes:
                        put(hmap, code, cid, True)
                else:
                    for code in hcodes:
                        put(hmap, code, cid)
                        put(vmap, code, cid)

            # Determine the "most popular" candidate.
            if unimap_h:
                self.cid2unichr_h[cid] = pick(unimap_h)
            if unimap_v or unimap_h:
                self.cid2unichr_v[cid] = pick(unimap_v or unimap_h)

        return

    def dump_cmap(self, fp, enc):
        data = dict(
            IS_VERTICAL=self.is_vertical.get(enc, False),
            CODE2CID=self.code2cid.get(enc),
        )
        json.dump(data, fp)

    def dump_unicodemap(self, fp):
        data = dict(
            CID2UNICHR_H=self.cid2unichr_h,
            CID2UNICHR_V=self.cid2unichr_v,
        )
        json.dump(data, fp)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--encoding-codec",
        "-c",
        type=str,
        action="append",
        default=[],
        help="Specify the codec of an encoding. Use `enc=codec` as a value.",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory where the compressed cmap's are stored.",
    )
    parser.add_argument(
        "regname",
        type=str,
    )
    parser.add_argument("cid2code", type=Path, nargs="*", help="Input cmaps.")
    return parser


def main(argv: List[Any]):
    parsed_args = create_parser().parse_args(argv[1:])

    encoding_codec: List[str] = parsed_args.encoding_codec
    outdir: Path = parsed_args.output_dir
    regname: str = parsed_args.regname
    cid2codes: List[Path] = parsed_args.cid2code

    converter = CMapConverter(
        dict([enc_codec.split("=") for enc_codec in encoding_codec])
    )

    for path in cid2codes:
        print(f"reading: {path}...")
        path.parent.mkdir(exist_ok=True)
        with path.open() as fp:
            converter.load(fp)

    outdir.mkdir(exist_ok=True)
    for enc in converter.get_encs():
        path = outdir / f"{enc}.json.gz"
        print(f"writing: {path}...")
        with gzip.open(path, "wt") as fp:
            converter.dump_cmap(fp, enc)

    path = outdir / f"to-unicode-{regname}.json.gz"
    print(f"writing: {path}...")
    with gzip.open(path, "wt") as fp:
        converter.dump_unicodemap(fp)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
