# 📝 pdfminer.six documentation

pdfminer.six docs are generated with
[Sphinx](https://www.sphinx-doc.org/en/master/), using
[reStructuredText](https://docutils.sourceforge.io/rst.html).

<br>
<br>

## How to build the documentation

pdfminer.six documentation can be found at
https://pdfminersix.readthedocs.io/en/latest/. If you want to build the
documentation locally, you can follow the steps below.

<br>

### Install the requirements

Before installing the requirements, you'd probably would want to create and
activate a Python virtual environment first:

```console
python -m venv venv
source venv/bin/activate
```

That way, you can easily clean up the installed packages later on by removing
the `venv` directory.

<br>

Once this is done, you can install the requirements:

```console
pip install -r requirements.txt
```

<br>

### Building the documentation

To build the documentation, simply run:

```console
make html
```

The generated docs will be placed in the `build/` directory. You can easily view
them on your browser by opening `build/html/index.html`.

<br>

**NOTE**: If you want to modify the documentation and are going to add/remove
elements from the toc-tree, it is recommended to clean up the `build` directory
before compiling again. To do this, you can run the following command:

```console
make clean && make html
```
