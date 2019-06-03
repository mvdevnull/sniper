'''
Build script for the nessrest module
'''
# Copyright (c) 2014-2015, Tenable Network Security, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#   - Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   - Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   - Neither the name of Tenable Network Security, Inc. nor the names of its
#     contributors may be used to endorse or promote products derived from this
#     software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, TITLE,
# NON-INFRINGEMENT, INTEGRATION, PERFORMANCE, AND ACCURACY AND ANY IMPLIED
# WARRANTIES ARISING FROM STATUTE, COURSE OF DEALING, COURSE OF PERFORMANCE, OR
# USAGE OF TRADE, ARE DISCLAIMED. IN NO EVENT SHALL TENABLE NETWORK SECURITY,
# INC., OR ANY SUCCESSOR-IN-INTEREST, BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from setuptools import setup
from codecs import open
from os import path
import nessrest

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

with open(path.join(here, "LICENSE"), encoding="utf-8") as f:
    license = f.read()

setup(name="nessrest",
      version=nessrest.__version__,
      packages=["nessrest"],
      include_package_data=True,
      exclude_package_data={'': ['*.pyc']},
      author="Scott Walsh, Ben Bergman, Matthew Everson, Matthew Woelk, Rich Walchuck",
      author_email="research@tenable.com",
      url="https://github.com/tenable/nessrest",
      include_dirs=["."],
      license=license,
      description="An interface to the Nessus 6 REST API",
      long_description=long_description,
      classifiers=[
          "Development Status :: 4 - Beta",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
      ],
      keywords="nessus nessrest ness_rest",
      install_requires=['requests >= 1.4'],
      scripts=['nessrest/ness_rest'])
