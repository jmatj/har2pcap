# -*- coding: utf-8 -*-
from subprocess import Popen, PIPE
import re
import struct


def resolve_mac(ip):
    Popen(["ping", "-c 1", ip], stdout=PIPE)
    pid = Popen(["arp", "-n", ip], stdout=PIPE)
    s = pid.communicate()[0]
    mac = re.search(b'(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', s).groups()[0]
    return mac.decode('UTF-8')
    
def encode_mac(mac):
    mac = mac.split(':')
    binary = b''
    for mac_byte in reversed(mac): # little endian
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

def number_to_64_bit(int_value):
    return struct.pack('<q', int_value)
