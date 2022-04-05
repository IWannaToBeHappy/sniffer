from ctypes import c_uint16, c_uint32
from .Protocol import Protocol

class UDP(Protocol):
    _fields_ = [
        ("sport", c_uint16),        # Source port
        ("dport", c_uint16),        # Destination port
        ("len", c_uint16),          # Header length
        ("chksum", c_uint16),       # header checksum
    ]

    def __init__(self, packet:bytes):
        super().__init__(packet)
        self.header_len = self.len
        self.info = {
            "sport":self.sport,
            "dport":self.dport
        }
