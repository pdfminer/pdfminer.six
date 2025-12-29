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
* Help others by sharing your thoughts in comments on issues and pull requests.
* Join the chat on [gitter](https://gitter.im/pdfminer-six/Lobby)

## Guideline for creating issues

* Search previous issues, as yours might be a duplicate.
* When creating a new issue for a bug, include a minimal reproducible example.
* When creating a new issue for a feature, be sure to describe the context of the problem you are trying to solve. This
  will help others to see the importance of your feature request.

## Guideline for creating pull request

* A pull request should close an existing issue. For example, use "Fix #123" to indicate that your PR fixes issue 123.
* Pull requests should be merged to master.
* Include unit tests when possible. In case of bugs, this will help to prevent the same mistake in the future. In case
  of features, this will show that your code works correctly.
* Code should work for Python 3.10+.
* Test your code by running `make check` (see below).
* New features should be well documented using docstrings.
* Check if the [README.md](../README.md) or [readthedocs](../docs/source) documentation needs to be updated.
* Check spelling and grammar.
* Don't forget to update the [CHANGELOG.md](CHANGELOG.md#[Unreleased]).

## Guideline for posting comments

* [Be cordial and positive](https://kennethreitz.org/essays/2013/01/27/be-cordial-or-be-on-your-way)

## Guidelines for publishing

* Publishing is automated. Add a YYYYMMDD version tag and GitHub workflows will do the rest.

## Guideline for dependencies

* This package is distributed under the [MIT license](LICENSE).
* All dependencies should be compatible with this license.
* Use [licensecheck](https://pypi.org/project/licensecheck/) to validate if new packages are compatible.

## Getting started

This project uses [uv](https://docs.astral.sh/uv/) for dependency management and development workflows.

1. Clone the repository

    ```sh
    git clone https://github.com/pdfminer/pdfminer.six
    cd pdfminer.six
    ```

2. Install uv

    Follow the installation instructions at [https://docs.astral.sh/uv/getting-started/installation/](https://docs.astral.sh/uv/getting-started/installation/)

    Quick install:
    ```sh
    # On macOS and Linux
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # On Windows
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    ```

3. Install dev dependencies

    ```sh
    make install
    ```

    This runs `uv sync` to install all dependencies in an isolated virtual environment.

4. Install pre-commit hooks (recommended)

    ```sh
    uv run pre-commit install
    ```

    This will automatically run formatting and linting checks before each commit.

5. Run all checks before committing

    ```sh
    make check
    ```

    This runs formatting, linting with auto-fixes, type checking, and tests.

    For individual commands, run `make help` to see all available targets.
