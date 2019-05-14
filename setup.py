#!/usr/bin/env python

from setuptools import setup
from os import path

root = path.abspath(path.dirname(__file__))
with open(path.join(root, 'README.md')) as infile:
    long_description = infile.read()

setup(
    name='aedkeyman',
    version='0.2',
    packages=['aedkeyman'],
    license='MIT',
    author='Justin Chouinard',
    author_email='justin.chouinard@netscout.com',
    description='Manage TLS keys on NETSCOUT Arbor Edge Defense',
    long_description=long_description,
    entry_points={
        'console_scripts': ['aedkeyman=aedkeyman.command_line:main'],
    },
    install_requires=[
        'requests', 'asn1'
    ],
)
