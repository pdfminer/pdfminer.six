.. _acro_forms:

How to extract AcroForm fields from a PDF using Python and PDFMiner
********************************

Before you start, make sure you have :ref:`installed pdfminer.six<install>`.

The second thing you need is a PDF with AcroForms (as found in PDF files with fillable forms or multiple choices).

It won't work for XFA forms.

.. code-block:: python

    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdftypes import resolve1, PDFObjRef
    from pdfminer.psparser import PSLiteral, PSKeyword
    from pdfminer import utils
    
    data = {}
    
    with open(file_path, 'rb') as fp:
        parser = PDFParser(fp)
        
        doc = PDFDocument(parser)
        res = resolve1(doc.catalog)

        if 'AcroForm' not in res:
            raise ValueError("No AcroForm Found")
            
        fields = resolve1(doc.catalog['AcroForm'])['Fields']

        for f in fields:
            field = resolve1(f)
            name, value = field.get('T'), field.get('V')

            # decode name
            name = name.decode()

            if value:

                # resolve indirect obj
                while isinstance(value, PDFObjRef):
                    value = resolve1(value)

                # decode PSLiteral, PSKeyword
                if isinstance(value, (PSLiteral, PSKeyword)):
                    value = value.name

                # decode bytes
                if isinstance(value, bytes):
                    value = utils.decode_text(value)

            data.update({name: value})    
              
                print(name, value)

This code snippet will print all the fields name and value and save them in the "data" dictionary.
