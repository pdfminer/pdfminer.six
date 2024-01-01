# Working on documentation

The pdfminer.six docs are generated with [Sphinx](https://www.sphinx-doc.org/en/master/), using
[reStructuredText](https://docutils.sourceforge.io/rst.html).

The documentation is hosted on https://pdfminersix.readthedocs.io/. 

## Deploying new documentation

New documentation is deployed automatically when PR's are merged.

## Building documentation locally

You can build the documentation locally on your machine using the following steps. 

1. (Recommended) create a and activate a Python virtual environment. 

    ```console
    python -m venv .venv
    source .venv/bin/activate
    ```
   
2. With the virtual environment activated, install the dependencies for building the documentation. 

    ```console
    pip install '.[docs]'
    ```
   
3. Build the documentation. 

    ```console
    make clean && make html
    ```

