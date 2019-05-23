from os import path

from setuptools import setup

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
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
    entry_points={
        'console_scripts': ['aedkeyman=aedkeyman.command_line:main'],
    },
    install_requires=[
        'asn1',
        'enum34',
        'mock',
        'future',
        'requests',
    ],
    test_suite='nose.collector',
)
