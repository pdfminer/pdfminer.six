import os

import nox


PYTHON_ALL_VERSIONS = ["3.8", "3.9", "3.10", "3.11", "3.12"]
PYTHON_MODULES = ["pdfminer", "tools", "tests", "noxfile.py", "setup.py"]


@nox.session
def format(session):
    session.install("black<23")
    # Format files locally with black, but only check in cicd
    if "CI" in os.environ:
        session.run("black", "--check", *PYTHON_MODULES)
    else:
        session.run("black", *PYTHON_MODULES)


@nox.session
def lint(session):
    session.install("flake8")
    session.run("flake8", *PYTHON_MODULES, "--count", "--statistics")


@nox.session
def types(session):
    session.install("mypy<1")
    session.run(
        "mypy",
        "--install-types",
        "--non-interactive",
        "--show-error-codes",
        *PYTHON_MODULES,
    )


@nox.session(python=PYTHON_ALL_VERSIONS)
def tests(session):
    session.install("pip<23")
    session.install("setuptools<58")
    session.install("-e", ".[dev]")
    session.run("pytest")


@nox.session
def docs(session):
    session.install("-e", ".[docs]")
    session.run(
        "python", "-m", "sphinx", "-b", "html", "docs/source", "docs/build/html"
    )
    session.run(
        "python", "-m", "sphinx", "-b", "doctest", "docs/source", "docs/build/doctest"
    )
