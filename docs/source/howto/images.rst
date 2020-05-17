.. _images:

How to extract images from a PDF
********************************

Before you start, make sure you have :ref:`installed pdfminer.six<install>`.
The second thing you need is a PDF with images. If you don't have one,
you can download `this research paper
<https://www.robots.ox.ac.uk/~vgg/publications/2012/parkhi12a/parkhi12a.pdf>`_
with images of cats and dogs and save it as `example.pdf`::

    $ curl https://www.robots.ox.ac.uk/~vgg/publications/2012/parkhi12a/parkhi12a.pdf --output example.pdf

Then run the :ref:`pdf2txt<api_pdf2txt>` command::

    $ pdf2txt.py example.pdf --output-dir cats-and-dogs

This command extracts all the images from the PDF and saves them into the
`cats-and-dogs` directory.
