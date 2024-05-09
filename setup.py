#!/usr/bin/env python
from setuptools import setup, find_packages

# create long description
with open('README.rst') as file:
    long_description = file.read()
with open('CHANGELOG.rst') as file:
    long_description += '\n\n' + file.read()

setup(
    name='httpsig',
    description="Secure HTTP request signing using the HTTP Signature draft specification",
    long_description=long_description,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords='http,authorization,api,web',
    author='Adam Knight',
    author_email='adam@movq.us',
    url='https://github.com/ahknight/httpsig',
    license='MIT',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=True,
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    install_requires=['pycryptodome>=3,<4', 'six'],
    test_suite="httpsig.tests",
)
