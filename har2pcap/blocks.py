import struct


def number_to_16_bit(int_value):
    return struct.pack('h', int_value)


def number_to_32_bit(int_value):
    return struct.pack('i', int_value)


def number_to_64_bit(int_value):
    return struct.pack('q', int_value)


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
        while len(binary) % 4 != 0:
            binary += b'\x00'

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
        super().__init__(bytes.fromhex('0A 0D 0D 0A'))
        self.byte_order_magic = bytes.fromhex('4D 3C 2B 1A')
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
            super().__init__(bytes.fromhex('01 00 00 00'))
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
    builder.write('demo.pcapng')
