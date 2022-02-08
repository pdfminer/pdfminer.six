import nox


PYTHON_ALL_VERSIONS = ["3.6", "3.7", "3.8", "3.9", "3.10"]


@nox.session
def lint(session):
    session.install("flake8")
    session.run("flake8", "pdfminer/", "tools/", "tests/", "--count", "--statistics")


@nox.session
def types(session):
    session.install("mypy")
    session.run(
        "mypy", "--install-types", "--non-interactive", "--show-error-codes", "."
    )


@nox.session(python=PYTHON_ALL_VERSIONS)
def tests(session):
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
