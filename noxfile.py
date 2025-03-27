import os

import nox

PYTHON_ALL_VERSIONS = ["3.9", "3.10", "3.11", "3.12", "3.13"]
PYTHON_MODULES = ["fuzzing", "pdfminer", "tools", "tests", "noxfile.py"]


@nox.session
def format(session):
    session.install("ruff==0.5.1")
    # Format files locally with black, but only check in cicd
    if "CI" in os.environ:
        session.run("ruff", "check")
        session.run("ruff", "format", "--check")
    else:
        session.run("ruff", "check", "--fix")
        session.run("ruff", "format")


@nox.session
def types(session):
    session.install("mypy<1", "pytest-mypy")
    session.run(
        "mypy",
        "--install-types",
        "--non-interactive",
        "--show-error-codes",
        *PYTHON_MODULES,
    )


@nox.session(python=PYTHON_ALL_VERSIONS)
def tests(session):
    session.install("pip")
    session.install("-e", ".[dev]")
    session.run("pytest")


@nox.session
def docs(session):
    session.install("pip")
    session.install("-e", ".[docs]")
    session.run(
        "python",
        "-m",
        "sphinx",
        "-b",
        "html",
        "docs/source",
        "docs/build/html",
    )
    session.run(
        "python",
        "-m",
        "sphinx",
        "-b",
        "doctest",
        "docs/source",
        "docs/build/doctest",
    )
