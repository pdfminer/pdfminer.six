# Contributing guidelines

Any contribution is appreciated! You might want to:

* Fix spelling errors
* Improve documentation
* Add tests for untested code
* Add new features
* Fix bugs

## How can I contribute?

* Use [issues](https://github.com/pdfminer/pdfminer.six/issues) to report bugs and features
    - If you report a bug in the results for a particular pdf, include that pdf. This allows others to replicate the
     issue. 
* Fix issues by [creating pull requests](https://help.github.com/en/articles/creating-a-pull-request).
* Help others by sharing your thoughs in comments on issues and pull requests.
* Join the chat on [gitter](https://gitter.im/pdfminer-six/Lobby)

## Guidelines for creating issues

* Search previous issues, as yours might be a duplicate.
* When creating a new issue for a bug, include a minimal reproducible example.
* When creating a new issue for a feature, be sure to describe the context of the problem you are trying to solve. This
  will help others to see the importance of your feature request. 

## Guideline for creating pull request

* A pull request should close an existing issue. For example, use "Fix #123" to indicate that your PR fixes issue 123. 
* Pull requests should be merged to master.
* Include unit tests when possible. In case of bugs, this will help to prevent the same mistake in the future. In case
  of features, this will show that your code works correctly.
* Code should work for Python 3.6+.
* Test your code by using nox (see below). 
* New features should be well documented using docstrings.
* Check if the [README.md](../README.md) or [readthedocs](../docs/source) documentation needs to be updated. 
* Check spelling and grammar.
* Don't forget to update the [CHANGELOG.md](CHANGELOG.md#[Unreleased]). 

## Guidelines for posting comments

* [Be cordial and positive](https://kennethreitz.org/essays/2013/01/27/be-cordial-or-be-on-your-way)

## Guidelines for publishing

* Publishing is automated. Add a YYYYMMDD version tag and GitHub workflows will do the rest. 

## Getting started

1. Clone the repository

    ```sh
    git clone https://github.com/pdfminer/pdfminer.six
    cd pdfminer.six
    ```

2. Install dev dependencies

    ```sh
    pip install -e .[dev]
    ```

3. Run the tests

    On all Python versions:

    ```sh
    nox
   ```
   
   Or on a single Python version:
   
   ```sh
    nox -e py36
    ```
