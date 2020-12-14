"""Setup script for realpython-reader"""

import os.path
from setuptools import setup

# The directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))

# The text of the README file
with open(os.path.join(HERE, "README.md")) as fid:
    README = fid.read()

# This call to setup() does all the work
setup(
    name="rbac_builder",
    version="1.0.1",
    description="Role Base Access Control Builder for Flask",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Kidataek",
    author_email="tuankiet.hcmc@gmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    packages=["rbac_builder"],
    include_package_data=True,
    install_requires=[
        "flask", "flask_sqlalchemy", "flask_jwt_extended"
    ]
)
