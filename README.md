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
Usage:
  har2pcapng [source-har-file] [destination-pcapng-file]

Options:
  -h --help             show this screen.
  --version             show version.
  -v --verbose          increase verbosity
  -q --quiet            suppress non-error messages

```
