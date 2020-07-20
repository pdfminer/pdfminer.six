.. _acro_forms:

How to extract AcroForm fields from a PDF using Python and PDFMiner
********************************

Before you start, make sure you have :ref:`installed pdfminer.six<install>`.

The second thing you need is a PDF with AcroForms (as found in PDF files with fillable forms or multiple choices).

It won't work for XFA forms, only AcroForm are not supported.

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


Initialize the parser and the PDFDocument objects

.. code-block:: python
    parser = PDFParser(fp)
    doc = PDFDocument(parser)

Get the catalog

.. code-block:: python
    res = resolve1(doc.catalog)

Check if the catalogs contains the AcroForm key and raise ValuError if not (the PDF does not contain Acroform)

.. code-block:: python
    if 'AcroForm' not in res:
        raise ValueError("No AcroForm Found")

Get the field list resolving the entry in the catalog
.. code-block:: python
    fields = resolve1(doc.catalog['AcroForm'])['Fields']
    for f in fields:
        field = resolve1(f)  # may need further resolving

Get field name and field value
.. code-block:: python
    name, value = field.get('T'), field.get('V')

Decode field name.
.. code-block:: python
    name = name.decode()

Resolve indirect field value objects
.. code-block:: python
    while isinstance(value, PDFObjRef):
        value = resolve1(value)

Decode PSLiteral and PSKeyword field values
.. code-block:: python
    if isinstance(value, (PSLiteral, PSKeyword)):
        value = value.name

Decode bytes field values
.. code-block:: python
    if isinstance(value, bytes):
        value = utils.decode_text(value)

