import hashlib
import struct
import binascii

from fiveserver import errors

def makePacketHeader(bs):
    """
    Create a packet header from a string buffer
    """
    if len(bs) < 8:
        raise ValueError("Buffer too short for packet header")
    
    id, length, packet_count = struct.unpack('!H H I', bs[:8])
    return PacketHeader(id, length, packet_count)


def readPacketHeader(stream):
    """
    Read bytes from the stream and create a packet header
    """
    bs = stream.read(8)
    if len(bs) < 8:
        raise ValueError("Stream does not contain enough bytes for header")
    return makePacketHeader(bs)

def verify_md5(expected_md5, packet):
    """
    Verify the MD5 checksum of a packet
    """
    if packet.md5.digest() != expected_md5:
        raise errors.NetworkError(
            f'Wrong MD5-checksum! (expected: {packet.md5.hexdigest()}, got: {binascii.b2a_hex(expected_md5)})'
        )

def makePacket(bs):
    """
    Read bytes from the stream and create a packet
    """
    if len(bs) < 24:
        raise ValueError("Buffer too short for a valid packet")
    
    header = makePacketHeader(bs[:8])
    md5 = bs[8:24]
    data = bs[24:24 + header.length]
    
    if len(data) != header.length:
        raise ValueError("Buffer does not contain enough data for the declared packet length")
    
    p = Packet(header, data)
    verify_md5(md5, p)
    return p

def readPacket(stream):
    """
    Read bytes from the stream and create a packet
    """
    header = readPacketHeader(stream)
    md5 = stream.read(16)
    data = stream.read(header.length)
    
    if len(md5) != 16 or len(data) != header.length:
        raise ValueError("Stream does not contain enough bytes for a complete packet")
    
    p = Packet(header, data)
    verify_md5(md5, p)
    return p

class PacketHeader:
    """
    Packet header (id, length, packet-counter)
    """
    def __init__(self, id, length, packet_count):
        self.id = id
        self.length = length
        self.packet_count = packet_count

    def __bytes__(self):
        return struct.pack('!H H I', self.id, self.length, self.packet_count)

    def __repr__(self):
        return f'PacketHeader(0x{self.id:04x},{self.length},{self.packet_count})'

class Packet:
    """ 
    Encapsulates a PES packet, which consists 
    of three things: header, md5, data
    """
    def __init__(self, header, data):
        self.header = header
        self.data = data
        self.md5 = hashlib.md5(bytes(header) + data)
        
    def __bytes__(self):
        return bytes(self.header) + self.md5.digest() + self.data

    def __repr__(self): 
        return f'Packet({repr(self.header)}, md5="{self.md5.hexdigest()}", data:"{binascii.b2a_hex(self.data)}")'

