from ctypes import c_uint16, c_uint32
from .Protocol import Protocol

class TCP(Protocol):
    _fields_ = [
        ("sport", c_uint16),        # Source port
        ("dport", c_uint16),        # Destination port
        ("seq", c_uint32),          # Sequence number
        ("ack", c_uint32),          # Acknowledgement number
        ("offset", c_uint16, 4),    # header length
        ("reserved", c_uint16, 3),  # Reserved field
        ("flags", c_uint16, 9),     # TCP flag codes
        ("window", c_uint16),       # Size of the receive window
        ("chksum", c_uint16),       # TCP header checksum
        ("urg", c_uint16),          # Urgent pointer
    ]
    
    def __init__(self, packet:bytes):
        super().__init__(packet)
        self.header_len = self.offset
        self.info = {
            "sport":self.sport,
            "dport":self.dport,
            "seq":self.seq,
            "ack":self.ack,
        }
