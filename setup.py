# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='har2pcap',
    version='0.0.1.dev',
    description='har to pcap converter',
    long_description=readme,
    author='Jonas Matter',
    author_email='jonasmatter@gmail.com',
    url='https://github.com/jmatj/har2pcap',
    license=license,
    entry_points={
        'console_scripts':
            ['har2pcap = har2pcap.cli:main']
    },
    packages=find_packages(exclude=('tests'))
)
