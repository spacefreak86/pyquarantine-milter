from setuptools import setup

def read_file(fname):
    with open(fname, 'r') as f:
        return f.read()

version = {}
exec(read_file("pyquarantine/version.py"), version)

setup(name = "pyquarantine",
    version = version["__version__"],
    author = "Thomas Oettli",
    author_email = "spacefreak@noop.ch",
    description = "A pymilter based sendmail/postfix pre-queue filter.",
    license = "GPL 3",
    keywords = "quarantine milter",
    url = "https://github.com/spacefreak86/pyquarantine-milter",
    packages = ["pyquarantine"],
    long_description = read_file("README.md"),
    long_description_content_type="text/markdown",
    classifiers = [
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Communications :: Email :: Filters"
    ],
    entry_points = {
        "console_scripts": [
            "pyquarantine-milter=pyquarantine.run:main",
            "pyquarantine=pyquarantine.cli:main"
        ]
    },
    install_requires = ["pymilter", "netaddr", "beautifulsoup4[lxml]", "peewee"],
    python_requires = ">=3.6"
)
