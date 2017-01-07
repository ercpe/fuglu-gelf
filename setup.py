#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

from fuglugelf import VERSION

setup(
    name='fuglu-gelf',
    version=VERSION,
    description='Fuglu plugin to log all mail information via GELF',
    author='Johann Schmitz',
    author_email='johann@j-schmitz.net',
    url='https://code.not-your-server.de/fuglu-gelf.git',
    download_url='https://code.not-your-server.de/fuglu-gelf.git/tags/',
    packages=find_packages(exclude=('tests', )),
    include_package_data=True,
    zip_safe=False,
    license='GPL-3',
)
