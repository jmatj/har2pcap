# -*- coding: utf-8 -*-
from subprocess import Popen, PIPE
import re

def resolve_mac(ip):
    Popen(["ping", "-c 1", ip], stdout=PIPE)
    pid = Popen(["arp", "-n", ip], stdout=PIPE)
    s = pid.communicate()[0]
    mac = re.search(b'(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', s).groups()[0]
    return mac.decode('UTF-8')