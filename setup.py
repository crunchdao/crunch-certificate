#!/usr/bin/env python3

import os
from typing import Any

from setuptools import find_packages, setup

package = "crunch_certificate"


about: dict[str, Any] = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, package, "__version__.py")) as f:
    exec(f.read(), about)

with open("requirements/default.txt") as fd:
    requirements = fd.read().splitlines()

with open("requirements/test.txt") as fd:
    test_requirements = fd.read().splitlines()

with open("README.md") as fd:
    readme = fd.read()

setup(
    name=about["__title__"],
    description=about["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    version=about["__version__"],
    author=about["__author__"],
    author_email=about["__author_email__"],
    url=about["__url__"],
    packages=find_packages(),
    package_data={
        package: [
            "web_sign.html",
        ]
    },
    python_requires=">=3",
    install_requires=requirements,
    extras_require={
        "test": test_requirements,
    },
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "crunch-certificate=crunch_certificate.cli:cli",
            "crunch-cert=crunch_certificate.cli:cli",
        ],
    },
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="package development template"
)
