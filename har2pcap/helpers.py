# -*- coding: utf-8 -*-
import struct
from urllib.parse import urlparse


def encode_mac(mac):
    mac = mac.split(':')
    binary = b''
    for mac_byte in reversed(mac):  # little endian
        binary += bytes.fromhex(mac_byte)
    return binary


def encode_ip(ip):
    ip = ip.split('.')
    binary = b''
    for ip_byte in ip:
        binary += number_to_8_bit_unsigned(int(ip_byte))
    return binary


def pad_to_32bits(data):
    """Add Padding to 32 bits (4 Bytes)"""
    if len(data) % 4 != 0:
        data += (4 - len(data) % 4) * b'\0'
    return data


def number_to_8_bit_unsigned(int_value):
    return struct.pack('<B', int_value)


def number_to_16_bit(int_value):
    return struct.pack('<h', int_value)


def number_to_16_bit_unsigned(int_value):
    return struct.pack('<H', int_value)


def number_to_32_bit(int_value):
    return struct.pack('<i', int_value)


def number_to_32_bit_big_endian(int_value):
    return struct.pack('>i', int_value)


def number_to_32_bit_unsigned(int_value):
    return struct.pack('<I', int_value)


def number_to_64_bit(int_value):
    return struct.pack('<q', int_value)


def number_to_64_bit_unsigned(int_value):
    return struct.pack('<Q', int_value)


def parse_request_uri(url):
    o = urlparse(url)
    return o.path
