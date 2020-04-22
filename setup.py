from setuptools import setup

def read_file(fname):
    with open(fname, 'r') as f:
        return f.read()

version = {}
exec(read_file("pymodmilter/version.py"), version)

setup(name = "pymodmilter",
    version = version["__version__"],
    author = "Thomas Oettli",
    author_email = "spacefreak@noop.ch",
    description = "A pymilter based sendmail/postfix pre-queue filter.",
    license = "GPL 3",
    keywords = "header milter",
    url = "https://github.com/spacefreak86/pymodmilter",
    packages = ["pymodmilter"],
    long_description = read_file("README.md"),
    long_description_content_type = "text/markdown",
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
    include_package_data = True,
    entry_points = {
        "console_scripts": [
            "pymodmilter=pymodmilter.run:main"
        ]
    },
    data_files = [
        (
            'usr/share/docs/',
            [
                'docs/pymodmilter.conf.example'
            ]
        )
    ],
    install_requires = ["pymilter", "netaddr"],
    python_requires = ">=3.6"
)
