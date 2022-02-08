from pdfminer.pdffont import PDFCIDFont
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.psparser import PSLiteral


def test_get_cmap_from_pickle():
    """Test if cmap file is read from pdfminer/cmap

    Regression test for https://github.com/pdfminer/pdfminer.six/issues/391
    """
    cmap_name = 'UniGB-UCS2-H'
    spec = {'Encoding': PSLiteral(cmap_name)}
    resource_manager = PDFResourceManager()
    font = PDFCIDFont(resource_manager, spec)

    cmap = font.get_cmap_from_spec(spec, False)

    assert cmap.attrs.get('CMapName') == cmap_name
    assert len(cmap.code2cid) > 0
