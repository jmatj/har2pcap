# -*- coding: utf-8 -*-
import os

def hmm():
    # -- start global header --
    # open file in binary mode
    target = open('test1.pcap', 'wb')
    # write magic number d4 c3 b2 a1 to identify pcap files
    target.write(bytes.fromhex('d4 c3 b2 a1'))
    # write major and minor version: version 2.4
    target.write(bytes.fromhex('02 00 04 00'))
    # write GMT timezone offset minus the timezone used in the headers in seconds
    # and the accuracy of the timestamps in the capture
    target.write(bytes.fromhex('00 00 00 00 00 00 00 00'))
    # write snapshot length ex. 65535 the default value for tcpdump and wireshark
    target.write(bytes.fromhex('ff ff 00 00 '))
    # write Link-Layer Header Type for Ethernet
    target.write(bytes.fromhex('01 00 00 00'))
    # -- end global header --

    # -- start packet header --
    # write timestamp in seconds (Unix Epoch)
    target.write(bytes.fromhex('c2 ba cd 4f'))
    # write microseconds part of the time at which the packet was captured
    target.write(bytes.fromhex('b6 35 0f 00'))
    # write the size of the saved packet data
    target.write(bytes.fromhex('36 00 00 00'))
    # write the length of the packet as it was captured on the wire.
    target.write(bytes.fromhex('36 00 00 00'))
    # -- end packet header --

    # -- start ethernet data --
    # ethernet destination address
    target.write(bytes.fromhex('00 12 cf e5 54 a0'))
    # ethernet source address
    target.write(bytes.fromhex('00 1f 3c 23 db d3'))
    # ethernet type: IPv4
    target.write(bytes.fromhex('08 00'))
    # -- end ethernet data --

    # -- start IPv4 data --
    # IPv4 header length (20 Bytes) and explicit congestion notification
    target.write(bytes.fromhex('45 00'))
    # IPv4 Total Length
    target.write(bytes.fromhex('01 d8'))
    # IPv4 Identification
    target.write(bytes.fromhex('56 c3'))
    # IPv4 Flags and Fragment offset
    target.write(bytes.fromhex('40 00'))
    # IPv4 Time to live
    target.write(bytes.fromhex('40'))
    # IPv4 Protocol: TCP
    target.write(bytes.fromhex('06'))
    # IPv4 Header checksum, make sure validation is disabled
    target.write(bytes.fromhex('e8 f3'))
    # IPv4 Source IP-Address
    target.write(bytes.fromhex('c0 a8 01 6e'))
    # IPv4 Destination IP-Address
    target.write(bytes.fromhex('42 93 f4 bf'))
    # -- end IPv4 data --

    # -- start TCP data --
    # TCP Source Port
    target.write(bytes.fromhex('e2 28'))
    # TCP Destination Port
    target.write(bytes.fromhex('00 50'))
    # TCP Sequence number
    target.write(bytes.fromhex('82 dd 20 b7'))
    # TCP Acknowledgment number
    target.write(bytes.fromhex('5a 0b cb 9d'))
    # TCP Header Length and Flags
    target.write(bytes.fromhex('80 18'))
    # TCP Window Size
    target.write(bytes.fromhex('00 e5'))
    # TCP Checksum, make sure validation is disabled
    target.write(bytes.fromhex('fb 33'))
    # TCP Urgent pointer
    target.write(bytes.fromhex('00 00'))
    # TCP Options
    target.write(bytes.fromhex('01 01 08 0a 00 0a 76 a0 3a 23 3b 32'))
    # -- end TCP data --

    # -- start HTTP data --
    # HTTP Request Method: GET
    target.write(bytes.fromhex('47 45 54'))
    # HTTP additional byte between these twos
    target.write(bytes.fromhex('20'))
    # HTTP Request URI: /
    target.write(bytes.fromhex('2f'))
    # HTTP additional byte between these twos
    target.write(bytes.fromhex('20'))
    # HTTP GET Request Version: HTTP/1.1
    target.write(bytes.fromhex('48 54 54 50 27 31 2e 31'))
    # HTTP additional bytes
    target.write(bytes.fromhex('0d 0a'))
    # HTTP Host: motherfuckingwebsite.com\r\n
    target.write(bytes.fromhex('48 6f 73 74 3a 20 6d 6f'))
    target.write(bytes.fromhex('74 68 65 72 66 75 63 6b'))
    target.write(bytes.fromhex('69 6e 67 77 65 62 73 69'))
    target.write(bytes.fromhex('74 65 2e 63 6f 6d 0d 0a'))
    # HTTP Connection: keep-alive\r\n
    target.write(bytes.fromhex('43 6f 6e 6e 65 63 74 69'))
    target.write(bytes.fromhex('6f 6e 3a 20 6b 65 65 70'))
    target.write(bytes.fromhex('2d 61 6c 69 76 65 0d 0a'))
    # HTTP Pragma: no-cache\r\n
    target.write(bytes.fromhex('50 72 61 67 6d 61 3a 20'))
    target.write(bytes.fromhex('6e 6f 2d 63 61 63 68 65'))
    target.write(bytes.fromhex('0d 0a'))
    # HTTP Cache-Control: no-cache\r\n
    target.write(bytes.fromhex('43 61 63 68 65 2d 43 6f'))
    target.write(bytes.fromhex('6e 74 72 6f 6c 3a 20 6e'))
    target.write(bytes.fromhex('6f 2d 63 61 63 68 65 0d'))
    target.write(bytes.fromhex('0a'))
    # HTTP Accept: text/html,application/xhtml+xml,...
    target.write(bytes.fromhex('41 63 63 65 70 74 3a 20'))
    target.write(bytes.fromhex('74 65 78 74 2f 68 74 6d'))
    target.write(bytes.fromhex('6c 2c 61 70 70 6c 69 63'))
    target.write(bytes.fromhex('61 74 69 6f 6e 2f 78 68'))
    target.write(bytes.fromhex('74 6d 6c 2b 78 6d 6c 2c'))
    target.write(bytes.fromhex('61 70 70 6c 69 63 61 74'))
    target.write(bytes.fromhex('69 6f 6e 2f 78 6d 6c 3b'))
    target.write(bytes.fromhex('71 3d 30 2e 39 2c 69 6d'))
    target.write(bytes.fromhex('61 67 65 2f 77 65 62 70'))
    target.write(bytes.fromhex('2c 2a 2f 2a 3b 71 3d 30'))
    target.write(bytes.fromhex('2e 38 0d 0a'))
    # HTTP Upgrade-Insecure-Requests: 1\r\n
    target.write(bytes.fromhex('55 70 67 72 61 64 65 2d'))
    target.write(bytes.fromhex('49 6e 73 65 63 75 72 65'))
    target.write(bytes.fromhex('2d 52 65 71 75 65 73 74'))
    target.write(bytes.fromhex('73 3a 20 31 0d 0a'))
    # HTTP User-Agent\r\n
    target.write(bytes.fromhex('55 73 65 72 2d 41 67 65'))
    target.write(bytes.fromhex('6e 74 3a 20 4d 6f 7a 69'))
    target.write(bytes.fromhex('6c 6c 61 2f 35 2e 30 20'))
    target.write(bytes.fromhex('28 58 31 31 3b 20 4c 69'))
    target.write(bytes.fromhex('6e 75 78 20 78 38 36 5f'))
    target.write(bytes.fromhex('36 34 29 20 41 70 70 6c'))
    target.write(bytes.fromhex('65 57 65 62 4b 69 74 2f'))
    target.write(bytes.fromhex('35 33 37 2e 33 36 20 28'))
    target.write(bytes.fromhex('4b 48 54 4d 4c 2c 20 6c'))
    target.write(bytes.fromhex('69 6b 65 20 47 65 63 6b'))
    target.write(bytes.fromhex('6f 29 20 43 68 72 6f 6d'))
    target.write(bytes.fromhex('65 2f 35 30 2e 30 2e 32'))
    target.write(bytes.fromhex('36 36 31 2e 39 34 20 53'))
    target.write(bytes.fromhex('61 66 61 72 69 2f 35 33'))
    target.write(bytes.fromhex('37 2e 33 36 0d 0a'))
    # HTTP Accept-Encoding\r\n
    target.write(bytes.fromhex('41 63 63 65 70 74 2d 45'))
    target.write(bytes.fromhex('6e 63 6f 64 69 6e 67 3a'))
    target.write(bytes.fromhex('20 67 7a 69 70 2c 20 64'))
    target.write(bytes.fromhex('65 66 6c 61 74 65 2c 20'))
    target.write(bytes.fromhex('73 64 63 68 0d 0a'))
    # HTTP Accept-Language: en-US,en;q=0.8\r\n
    target.write(bytes.fromhex('41 63 63 65 70 74 2d 4c'))
    target.write(bytes.fromhex('61 6e 67 75 61 67 65 3a'))
    target.write(bytes.fromhex('20 65 6e 2d 55 53 2c 65'))
    target.write(bytes.fromhex('6e 3b 71 3d 30 2e 38 0d'))
    target.write(bytes.fromhex('0a'))
    # HTTP End \r\n
    target.write(bytes.fromhex('0d 0a'))
    # -- end HTTP data --

    target.close()

