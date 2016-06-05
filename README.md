# har2pcap

har2pcap converts .har (HTTP Archive Viewer) files into the pcapng file format - which can be analyzed with [Wireshark](https://www.wireshark.org)

## Installation

Python3 (!) and [Pip](pip) must be installed.

If so, run the following commands to setup the project

```bash
# create virtualenv
virtualenv -p python3 venv
# activate virtualenv
source venv/bin/activate

# install requirements
- make

# run tests
- make test

# ... do your work here

# deactivate virtualenv
- deactivate
```

## Usage
```
usage: har2pcap [-h] [--version] har-file pcap-file

Convert har to pcapng

positional arguments:
  har-file    Tha .har file to convert
  pcap-file   The destination .pcapng file

optional arguments:
  -h, --help  show this help message and exit
  --version   show program's version number and exit

```
