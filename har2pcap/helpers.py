# -*- coding: utf-8 -*-
from subprocess import Popen, PIPE
import re


def resolve_mac(ip):
    Popen(["ping", "-c 1", ip], stdout=PIPE)
    pid = Popen(["arp", "-n", ip], stdout=PIPE)
    s = pid.communicate()[0]
    mac = re.search(b'(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', s).groups()[0]
    return mac.decode('UTF-8')
    
def pad_to_32bits(data):
    """Add Padding to 32 bits (4 Bytes)"""
    if len(data) % 4 != 0:
        data += (4 - len(data) % 4) * b'\0'
    return data
