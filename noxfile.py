"""
Nox configuration for formatting, type checking, testing, and docs building.
"""

import os
import nox

PYTHON_ALL_VERSIONS = ["3.9", "3.10", "3.11", "3.12", "3.13"]
PYTHON_MODULES = ["fuzzing", "pdfminer", "tools", "tests", "noxfile.py"]


@nox.session(reuse_venv=True)
def format(session):
    """Run Ruff for linting & formatting."""
    session.install("ruff==0.5.1")

    if os.getenv("CI"):
        # CI: check only, no auto-fix
        session.run("ruff", "check")
        session.run("ruff", "format", "--check")
    else:
        # Local development: apply fixes
        session.run("ruff", "check", "--fix")
        session.run("ruff", "format")


@nox.session(reuse_venv=True)
def types(session):
    """Run static type checking."""
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
    """Run the test suite across multiple Python versions."""
    session.install("pip>=21")
    session.install("-e", ".[dev]")
    session.run("pytest")


@nox.session(reuse_venv=True)
def docs(session):
    """Build documentation and doctests."""
    session.install("pip>=21")
    session.install("-e", ".[docs]")

    # HTML build
    session.run(
        "python", "-m", "sphinx", "-b", "html",
        "docs/source", "docs/build/html",
    )

    # Doctest build
    session.run(
        "python", "-m", "sphinx", "-b", "doctest",
        "docs/source", "docs/build/doctest",
    )
