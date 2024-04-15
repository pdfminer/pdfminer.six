from pathlib import Path
from setuptools import setup

root_dir = Path(__file__).parent
with open(root_dir / "README.md", "rt") as f:
    readme = f.read()

setup(
    name="pdfminer.rtl",
    setuptools_git_versioning={
        "enabled": True,
    },
    setup_requires=["setuptools-git-versioning<2"],
    packages=["pdfminer"],
    package_data={"pdfminer": ["cmap/*.pickle.gz", "py.typed"]},
    install_requires=[
        "charset-normalizer >= 2.0.0",
        "cryptography >= 36.0.0",
        'typing_extensions; python_version < "3.8"',
        'importlib_metadata; python_version < "3.8"',
        'python-bidi',
    ],
    extras_require={
        "dev": ["pytest", "nox", "black", "mypy == 0.931"],
        "docs": ["sphinx", "sphinx-argparse"],
        "image": ["Pillow"],
    },
    description="PDF parser and analyzer",
    long_description=readme,
    long_description_content_type="text/markdown",
    license="MIT",
    author="Yusuke Shinyama + Philippe Guglielmetti",
    author_email="pdfminer@goulu.net",
    url="https://github.com/taneron/pdfminerrtl",
    scripts=[
        "tools/pdf2txt.py",
        "tools/dumppdf.py",
    ],
    keywords=[
        "pdf parser",
        "pdf converter",
        "layout analysis",
        "text mining",
    ],
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3 :: Only",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Topic :: Text Processing",
    ],
)
