from setuptools import setup

def read_file(fname):
    with open(fname, 'r') as f:
        return f.read()

setup(name = "pyquarantine",
    author = "Thomas Oettli",
    author_email = "spacefreak@noop.ch",
    description = "A pymilter based sendmail/postfix pre-queue filter.",
    license = "GPL 3",
    keywords = "header quarantine milter",
    url = "https://github.com/spacefreak86/pyquarantine",
    packages = ["pyquarantine"],
    long_description = read_file("README.md"),
    long_description_content_type = "text/markdown",
    classifiers = [
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Communications :: Email :: Filters"
    ],
    include_package_data = True,
    entry_points = {
        "console_scripts": [
            "pyquarantine-milter=pyquarantine.run:main",
            "pyquarantine=pyquarantine.cli:main",
        ]
    },
    data_files = [
        (
            "/etc/pyquarantine",
            [
                "pyquarantine/misc/pyquarantine.conf.default"
            ]
        ), (
            "/etc/pyquarantine/templates",
            [
                "pyquarantine/misc/templates/disclaimer_html.template",
                "pyquarantine/misc/templates/disclaimer_text.template",
                "pyquarantine/misc/templates/notification.template",
                "pyquarantine/misc/templates/removed.png"
            ]
        )
    ],
    install_requires = ["pymilter >= 1.5", "jsonschema", "netaddr", "beautifulsoup4[lxml]", "peewee"],
    python_requires = ">=3.9"
)
