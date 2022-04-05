from ctypes import c_ubyte, c_uint16
from .Protocol import Protocol


class Ethernet(Protocol):
    _fields_ = [("dst", c_ubyte * 6), ("src", c_ubyte * 6), ("eth", c_uint16)]
    entertypes = {
        0x0000: "Unknown",
        0x00BB: "Extreme Networks Discovery Protocol",
        0x0200: "PUP protocol",
        0x0800: "IP protocol",
        0x0806: "address resolution protocol",
        0x88A2: "AoE protocol",
        0x2000: "Cisco Discovery Protocol",
        0x2004: "Cisco Dynamic Trunking Protocol",
        0x8035: "reverse addr resolution protocol",
        0x8100: "IEEE 802.1Q VLAN tagging",
        0x88A8: "IEEE 802.1ad",
        0x9100: "Legacy QinQ",
        0x9200: "Legacy QinQ",
        0x8137: "Internetwork Packet Exchange",
        0x86DD: "IPv6 protocol",
        0x880B: "PPP",
        0x8847: "MPLS",
        0x8848: "MPLS Multicast",
        0x8863: "PPP Over Ethernet Discovery Stage",
        0x8864: "PPP Over Ethernet Session Stage",
        0x88CC: "Link Layer Discovery Protocol",
        0x6558: "Transparent Ethernet Bridging",
        0x8892: "PROFINET protocol",
    }

    def __init__(self, packet: bytes) -> None:
        super().__init__(packet)
        self.dest = self.addr_array_to_hdwr(self.dst)
        self.source = self.addr_array_to_hdwr(self.src)
        # 只能识别entertypes中的下层协议
        self.encapsulated_proto = self.entertypes.get(self.eth, None)
        self.info = {
            "dst": self.dest,
            "src": self.source,
            "type": self.encapsulated_proto,
        }
        self.header_len = 14
