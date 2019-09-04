from setuptools import setup

def read_file(fname):
    with open(fname, 'r') as f:
        return f.read()

setup(name = "pyheadermilter",
    version = "0.0.1",
    author = "Thomas Oettli",
    author_email = "spacefreak@noop.ch",
    description = "A pymilter based sendmail/postfix pre-queue filter.",
    license = "GPL 3",
    keywords = "header milter",
    url = "https://github.com/spacefreak86/pyheader-milter",
    packages = ["pyheadermilter"],
    long_description = read_file("README.md"),
    classifiers = [
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Communications :: Email :: Header"
    ],
    entry_points = {
        "console_scripts": [
            "pyheader-milter=pyheadermilter:main"
        ]
    },
    install_requires = ["pymilter", "netaddr"],
    python_requires = ">=3"
)
