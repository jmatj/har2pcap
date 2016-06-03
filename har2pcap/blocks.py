import helpers
import struct


def number_to_16_bit(int_value):
    return struct.pack('<h', int_value)


def number_to_32_bit(int_value):
    return struct.pack('<i', int_value)


def number_to_64_bit(int_value):
    return struct.pack('<q', int_value)


class Option:
    def __init__(self, code, value):
        """
        The given code(integer)
        Note that the given `value` must be a byte like value!
        """
        self.code = code
        self.value = value

    def binary(self):
        option_lenght = len(self.value)
        binary = self.value

        # Padding....
        binary = helpers.pad_to_32bits(binary)

        return number_to_16_bit(self.code) + number_to_16_bit(option_lenght) + binary


END_OF_OPTIONS = Option(0, b'')


class Block:

    def __init__(self, blocktype):
        """
        Blocktype must be 32 bits
        """
        self.blocktype = blocktype

    def binary(self):
        binary = self._binary()
        # Calculate size (plus 4 Bytes Block Type and 2x 4 Bytes Block Total Length)
        total_lenght = len(binary) + 12

        # Prepend Block Type and Bock Total Lenght
        binary = self.blocktype + number_to_32_bit(total_lenght) + binary

        # Append Block Total Lenght
        binary += number_to_32_bit(total_lenght)
        return binary


class SectionHeaderBlock(Block):

    def __init__(self):
        super().__init__(b'\x0A\x0D\x0D\x0A')
        self.byte_order_magic = b'\x4D\x3C\x2B\x1A'
        self.major_version = 1
        self.minor_version = 0
        self.section_lenght = -1

    def _binary(self):
        binary = self.byte_order_magic
        binary += number_to_16_bit(self.major_version)
        binary += number_to_16_bit(self.minor_version)
        binary += number_to_64_bit(self.section_lenght)
        return binary


class InterfaceDescriptionBlock(Block):

    def __init__(self, options, link_type=1, snap_len=262144):
        """
        Default link type is Ethernet.
        See http://www.tcpdump.org/linktypes.html for valid link types.
        """
        super().__init__(b'\x01\x00\x00\x00')
        self.link_type = link_type
        self.snap_len = snap_len
        self.options = options

    def _binary(self):
        binary = number_to_16_bit(self.link_type)

        # Reserved
        binary += number_to_16_bit(0)

        binary += number_to_32_bit(self.snap_len)

        for option in self.options:
            binary += option.binary()

        if len(self.options) > 0 and self.options[-1] is not END_OF_OPTIONS:
            binary += END_OF_OPTIONS.binary()
        return binary


class EnhancedPacketBlock(Block):

    def __init__(self, timestamp, packet_data, options):
        super().__init__(b'\x06\x00\x00\x00')
        self.interface_id = 0
        self.timestamp_high, self.timestamp_low = self._convert_timestamp(timestamp)
        self.packet_data = helpers.pad_to_32bits(packet_data)
        self.options = options
        self.captured_length = len(packet_data)
        self.original_length = self.captured_length

    def _binary(self):
        binary = number_to_32_bit(self.interface_id)
        binary += number_to_32_bit(self.timestamp_high)
        binary += number_to_32_bit(self.timestamp_low)
        binary += number_to_32_bit(self.captured_length)
        binary += number_to_32_bit(self.original_length)
        binary += self.packet_data

        for option in self.options:
            binary += option.binary()

        if len(self.options) > 0 and self.options[-1] is not END_OF_OPTIONS:
            binary += END_OF_OPTIONS.binary()

        return binary

    def _convert_timestamp(self, timestamp):
        mask_low = int.from_bytes(b'\xff\xff\xff\xff')
        timestamp_high = timestamp >> 32
        timestamp_low = timestamp & mask_low
        return timestamp_high, timestamp_low


class PcapngBuilder:
    def __init__(self):
        self.blocks = []

    def add_block(self, block):
        self.blocks.append(block)

    def write(self, path):
        with open(path, 'wb') as f:
            for block in self.blocks:
                f.write(block.binary())

if __name__ == '__main__':
    builder = PcapngBuilder()
    builder.add_block(SectionHeaderBlock())
    builder.add_block(InterfaceDescriptionBlock([
         Option(2, b'enp0s25'),  # 'if_name'
         Option(9, b'\x09'),  # 'if_tsresol'
         Option(12, b'Linux 4.4.0-22-generic')  # 'if_os'
         ]))

    # builder.add_block(EnhancedPacketBlock())
    builder.write('demo.pcapng')
