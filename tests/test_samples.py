import glob
import filecmp
import unittest

from samples import getpath
from tools import pdf2txt


# Use regen_refs to regenerate the reference files to which the outputs
# will be checked against
def pdf2txt_and_cmp(in_file, output_formats=None, additional_args=None,
                    regen_refs=False):
    if output_formats is None:
        output_formats = ["text"]

    for fmt in output_formats:
        ext = "txt" if fmt == "text" else format
        out_path = in_file.rstrip(".pdf") + "." + ext

        out_paths = [out_path]
        expected_contents_path = out_path + ".ref"
        if regen_refs:
            out_paths.append(expected_contents_path)

        for p in out_paths:
            args = ["-p1", "-V", "-t", fmt, "-o", p, in_file]
            if additional_args is not None:
                args += additional_args
            # display the equivalent command
            print("python tools/pdf2txt.py " + " ".join(args))
            pdf2txt.main(args)

        if not filecmp.cmp(out_path, expected_contents_path):
            raise Exception("Parsing of %s to %s do not match excepted in %s" %
                            (in_file, out_path, expected_contents_path))


class TestVerifyParsingOutput(unittest.TestCase):
    def test_verify_free(self):
        free_dir = getpath("")
        for p in glob.glob(free_dir + "/*.pdf"):
            pdf2txt_and_cmp(p)

    def test_verify_nonfree(self):
        nonfree_dir = getpath("nonfree")
        for p in glob.glob(nonfree_dir + "/*.pdf"):
            pdf2txt_and_cmp(p)

    def test_verify_encrypted(self):
        encryption_dir = getpath("encryption")
        passwords = ("foo", "baz")
        for p in glob.glob(encryption_dir + "/*.pdf"):
            # Only output xml, this is specifically testing encryption, not our
            # ability to parse to various formats
            for pw in passwords:
                pdf2txt_and_cmp(p, additional_args=["-P", pw])
