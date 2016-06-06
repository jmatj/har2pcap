import json
import datetime
from helpers import parse_request_uri
from packet import (EthPacket, IPv4Packet, TCPPacket, HTTPRequestPacket,
                    HTTPResponsePacket, PacketBuilder)


def parse_har(url):
    with open(url) as json_file:
        return json.load(json_file)['log']


def build_packets(har):
    """Return a list of HTTP packets with complete TCP/IP stack"""
    packets = []
    for entry in har['entries']:
        start_time = datetime.datetime.strptime(
            entry['startedDateTime'], '%Y-%m-%dT%H:%M:%S.%fZ').timestamp()
        timestamp = int(start_time * 1e6 + entry['time'] * 1e3)
        packet = {
            'timestamp': timestamp,
            'request': build_request_packet(entry['request']),
            'response': build_response_packet(entry['response'])
        }
        packets.append(packet)
    return packets


def build_request_packet(packet):
    eth_packet = EthPacket('ab:cd:ef:12:34:56', '65:43:21:fe:dc:ba')
    ip_packet = IPv4Packet('192.168.0.1', '8.8.8.8')
    tcp_packet = TCPPacket(34567, 80)

    http_headers = packet['headers']
    http_content = ''
    http_packet = HTTPRequestPacket(
        packet['method'], parse_request_uri(packet['url']),
        packet['httpVersion'], http_headers, http_content)
    builder = PacketBuilder(eth_packet, ip_packet, tcp_packet, http_packet)
    return builder.binary()


def build_response_packet(packet):
    eth_packet = EthPacket('65:43:21:fe:dc:ba', 'ab:cd:ef:12:34:56')
    ip_packet = IPv4Packet('8.8.8.8', '192.168.0.1')
    tcp_packet = TCPPacket(34567, 80)

    http_headers = packet['headers']
    if 'text' in packet['content']:
        http_content = packet['content']['text']
    else:
        http_content = ''
    http_packet = HTTPResponsePacket(
        packet['status'], packet['statusText'], packet['httpVersion'],
        http_headers, http_content)
    builder = PacketBuilder(eth_packet, ip_packet, tcp_packet, http_packet)
    return builder.binary()


if __name__ == "__main__":
    har = parse_har('../example.org.har')
    http_packets = build_packets(har)
