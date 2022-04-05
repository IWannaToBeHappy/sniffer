from ctypes import c_ubyte, c_uint16, c_uint8
from .Protocol import Protocol

class ICMP(Protocol):
    _fields_ = [
        ("type", c_uint8),      # Control message type
        ("code", c_uint8),      # Control message subtype
        ("chksum", c_uint16),   # Header checksum
        ("rest", c_ubyte * 4)   # Rest of header (contents vary)
    ]

    header_len = 8
    icmp_types = {
        0:"REPLY",
        8:"REQUEST"
    }

    def __init__(self, packet:bytes):
        super().__init__(packet)
        self.type_txt = self.icmp_types.get(self.type,"OTHER")
        self.info = {
            "icmp_type":self.type_txt
        }