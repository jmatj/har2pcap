import argparse
import os
from . import __VERSION__, har_to_pcapng


def _valid_har(file_name):
    if os.path.exists(file_name):
        return open(file_name, 'r')
    raise argparse.ArgumentTypeError('The given har file does not exist!')


def _valid_pcapng(file_name):
    if not os.path.exists(file_name):
        return open(file_name, 'wb')
    raise argparse.ArgumentTypeError('File %s already exists' % file_name)


def main():
    parser = argparse.ArgumentParser(description='Convert har to pcapng')
    parser.add_argument('har-file', metavar='har-file', type=_valid_har,
                        help='Tha .har file to convert')
    parser.add_argument('pcapng-file', metavar='pcap-file', type=_valid_pcapng,
                        help='The destination .pcapng file')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __VERSION__)

    args = vars(parser.parse_args())
    har_to_pcapng(args['har-file'], args['pcapng-file'])


if __name__ == '__main__':
    main()
