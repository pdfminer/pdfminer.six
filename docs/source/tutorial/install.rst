.. _install:

Install pdfminer.six as a Python package
****************************************

To use pdfminer.six for the first time, you need to install the Python
package in your Python environment.

This tutorial requires you to have a system with a working Python and pip
installation. If you don't have one and don't know how to install it, take a
look at `The Hitchhiker's Guide to Python! <https://docs.python-guide.org/>`_.

Install using pip
=================

Run the following command on the commandline to install pdfminer.six as a
Python package::

    pip install pdfminer.six


Test pdfminer.six installation
==============================

You can test the pdfminer.six installation by importing it in Python.

Open an interactive Python session from the commandline import pdfminer
.six::

    >>> import pdfminer
    >>> print(pdfminer.__version__)  # doctest: +IGNORE_RESULT
    '<installed version>'

Now you can use pdfminer.six as a Python package. But pdfminer.six also
comes with a couple of useful commandline tools. To test if these tools are
correctly installed, run the following on your commandline::

    $ pdf2txt.py --version
    pdfminer.six <installed version>
