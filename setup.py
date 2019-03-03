from setuptools import setup

def read_file(fname):
    with open(fname, 'r') as f:
        return f.read()

setup(name = "pyquarantine",
    version = "1.0.0",
    author = "Thomas Oettli",
    author_email = "spacefreak86@gmx.ch",
    description = "A milter to handle multiple quarantines.",
    license = "GPL 3",
    keywords = "quarantine milter",
    url = "https://github.com/spacefreak86/pyquarantine-milter",
    packages = ["pyquarantine"],
    long_description = read_file("README.md"),
    classifiers = [
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Topic :: Communications :: Email :: Quarantine"
    ],
    entry_points = {
        "console_scripts": [
            "pyquarantine-milter=pyquarantine.run:main"
        ]
    },
    install_requires = ["pymilter", "peewee"],
    python_requires = ">=2.7,<3"
) 
