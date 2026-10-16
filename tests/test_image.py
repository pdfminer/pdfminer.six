import os
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from pdfminer.image import ImageWriter


class TestImageWriterName:
    def test_traversal_name_stays_in_outdir(self):
        with TemporaryDirectory() as outdir:
            writer = ImageWriter(outdir)
            image = SimpleNamespace(name="../../../etc/passwd")
            name, path = writer._create_unique_image_name(image, ".jpg")
            assert os.sep not in name
            resolved = os.path.realpath(path)
            root = os.path.realpath(outdir)
            assert resolved.startswith(root + os.sep)

    def test_backslash_and_nul_are_stripped(self):
        with TemporaryDirectory() as outdir:
            writer = ImageWriter(outdir)
            image = SimpleNamespace(name="..\\..\\evil\x00")
            name, path = writer._create_unique_image_name(image, ".jpg")
            assert "\\" not in name and "\x00" not in name
            assert os.path.dirname(os.path.realpath(path)) == os.path.realpath(outdir)

    def test_plain_name_is_preserved(self):
        with TemporaryDirectory() as outdir:
            writer = ImageWriter(outdir)
            image = SimpleNamespace(name="Im1")
            name, _path = writer._create_unique_image_name(image, ".jpg")
            assert name == "Im1.jpg"
