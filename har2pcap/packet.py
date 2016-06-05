from helpers import encode_mac, encode_ip, number_to_16_bit_unsigned


class EthPacket:
    def __init__(self, source, destination, eth_type=b'\x08\x00'):
        self.source = source
        self.destination = destination
        self.eth_type = eth_type

    def binary(self):
        binary = encode_mac(self.source)
        binary += encode_mac(self.destination)
        binary += self.eth_type
        return binary


class IPv4Packet:
    def __init__(self, source, destination, transport_protocol=b'\x06'):
        self.version_header_len = b'\x45'
        self.dscp_ecn = b'\0'
        self.total_lenght = b'\x00\x00'
        self.identification = b'\x12\x34'  # arbitrary
        self.flags = b'\x40'  # don't fragment
        self.frag_offset = b'\0'
        self.ttl = b'\x40'  # = 64
        self.protocol = transport_protocol
        self.checksum = b'\x00\x00'
        self.source = source
        self.destination = destination

    def binary(self):
        binary = self.version_header_len
        binary += self.dscp_ecn
        binary += self.total_lenght
        binary += self.identification
        binary += self.flags
        binary += self.frag_offset
        binary += self.ttl
        binary += self.protocol
        binary += self.checksum
        binary += encode_ip(self.source)
        binary += encode_ip(self.destination)

        return binary


class TCPPacket:
    def __init__(self, source_port, dest_port):
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_nr = b'\x00\x00\x00\x00'
        self.ack_nr = b'\x00\x00\x00\x00'
        self.header_len = b'\x50'  # = 5 * 32 Bits = 20B
        self.flags = b'\x18'
        self.wind_size = b'\x00\xE5'
        self.checksum = b'\x00\x00'
        self.urg_pointer = b'\x00\x00'

    def binary(self):
        binary = number_to_16_bit_unsigned(self.source_port)
        binary += number_to_16_bit_unsigned(self.dest_port)
        binary += self.seq_nr
        binary += self.ack_nr
        binary += self.header_len
        binary += self.flags
        binary += self.wind_size
        binary += self.checksum
        binary += self.urg_pointer

        return binary


class HTTPPacket:
    def __init__(self, version, headers, content):
        self.version = version
        self.headers = headers
        self.content = content

    def binary(self):
        http_str = self._build_http_string()
        return str.encode(http_str, encoding='utf-8')

    def _build_http_string(self):
        http_str = self._build_http_begin()
        http_str += '\r\n'
        for header in self.headers:
            http_str += '{}: {}\r\n'.format(header['name'], header['value'])
        http_str += '\r\n'
        http_str += self.content

        return http_str


class HTTPRequestPacket(HTTPPacket):
    def __init__(self, method, request_uri, version, headers, content):
        super().__init__(version, headers, content)
        self.method = method
        self.request_uri = request_uri

    def _build_http_begin(self):
        return '{} {} {}'.format(self.method, self.request_uri, self.version)


class HTTPResponsePacket(HTTPPacket):
    def __init__(self, status_code, status_text, version, headers, content):
        super().__init__(version, headers, content)
        self.status_code = status_code
        self.status_text = status_text

    def _build_http_begin(self):
        return '{} {} {}'.format(
            self.version, self.status_code, self.status_text)


class PacketBuilder:
    def __init__(self, eth_packet, ipv4_packet, tcp_packet, http_packet):
        self.eth_packet = eth_packet
        self.ipv4_packet = ipv4_packet
        self.tcp_packet = tcp_packet
        self.http_packet = http_packet

    def binary(self):
        binary = self.eth_packet.binary()
        binary += self.ipv4_packet.binary()
        binary += self.tcp_packet.binary()
        binary += self.http_packet.binary()
        return binary

if __name__ == "__main__":
    eth_packet = EthPacket('ab:cd:ef:12:34:56', '65:43:21:fe:dc:ba')
    ip_packet = IPv4Packet('192.168.0.1', '8.8.8.8')
    tcp_packet = TCPPacket(34567, 80)

    http_headers = {
        'Host': 'www.google.com',
        'Accept': 'text/html',
        'Connection': 'keep-alive'
    }
    http_content = '<html><body>Hello World!</body></html>'
    http_packet = HTTPRequestPacket(
        'GET', '/index.html', 'HTTP/1.1', http_headers, http_content)

    builder = PacketBuilder(eth_packet, ip_packet, tcp_packet, http_packet)
    with open('packet-test', 'wb') as f:
        f.write(builder.binary())
