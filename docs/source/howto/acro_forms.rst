.. _acro_forms:

How to extract AcroForm interactive form fields from a PDF using PDFMiner
********************************

Before you start, make sure you have :ref:`installed pdfminer.six<install>`.

The second thing you need is a PDF with AcroForms (as found in PDF files with fillable forms or multiple choices). There are some examples of these in the GitHub repository under `samples/acroform`.

Only AcroForm interactive forms are supported, XFA forms are not supported.

.. code-block:: python

    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdftypes import resolve1
    from pdfminer.psparser import PSLiteral, PSKeyword
    from pdfminer.utils import decode_text    
    
    
    data = {}
 
 
    def decode_value(value):

        # decode PSLiteral, PSKeyword
        if isinstance(value, (PSLiteral, PSKeyword)):
            value = value.name

        # decode bytes
        if isinstance(value, bytes):
            value = decode_text(value)

        return value


    with open(file_path, 'rb') as fp:
        parser = PDFParser(fp)
        
        doc = PDFDocument(parser)
        res = resolve1(doc.catalog)

        if 'AcroForm' not in res:
            raise ValueError("No AcroForm Found")
            
        fields = resolve1(doc.catalog['AcroForm'])['Fields']  # may need further resolving

        for f in fields:
            field = resolve1(f)
            name, values = field.get('T'), field.get('V')

            # decode name
            name = decode_text(name)

            # resolve indirect obj
            values = resolve1(values)
            
            # decode value(s)
            if isinstance(values, list):
                values = [decode_value(v) for v in values]
            else:
                values = decode_value(values)

            data.update({name: values})    
              
            print(name, values)

This code snippet will print all the fields name and value and save them in the "data" dictionary.


How it works:

- Initialize the parser and the PDFDocument objects

.. code-block:: python

    parser = PDFParser(fp)
    doc = PDFDocument(parser)

- Get the catalog
(the catalog contains references to other objects defining the document structure, see section 7.7.2 of PDF 32000-1:2008 specs: https://www.adobe.com/devnet/pdf/pdf_reference.html)

.. code-block:: python

    res = resolve1(doc.catalog)

- Check if the catalog contains the AcroForm key and raise ValueError if not 
(the PDF does not contain Acroform type of interactive forms if this key is missing in the catalog, see section 12.7.2 of PDF 32000-1:2008 specs)

.. code-block:: python

    if 'AcroForm' not in res:
        raise ValueError("No AcroForm Found")

- Get the field list resolving the entry in the catalog

.. code-block:: python

    fields = resolve1(doc.catalog['AcroForm'])['Fields']
    for f in fields:
        field = resolve1(f)

- Get field name and field value(s)

.. code-block:: python

    name, values = field.get('T'), field.get('V')

- Decode field name.

.. code-block:: python

    name = decode_text(name)

- Resolve indirect field value objects

.. code-block:: python

    values = resolve1(value)

- Call the value(s) decoding method as needed
(a single field can hold multiple values, for example a combo box can hold more than one value at time)

.. code-block:: python

    if isinstance(values, list):
        values = [decode_value(v) for v in values]
    else:
        values = decode_value(values)
        
(the decode_value method takes care of decoding the fields value returning a string)

- Decode PSLiteral and PSKeyword field values

.. code-block:: python

    if isinstance(value, (PSLiteral, PSKeyword)):
        value = value.name

- Decode bytes field values

.. code-block:: python

    if isinstance(value, bytes):
        value = utils.decode_text(value)
