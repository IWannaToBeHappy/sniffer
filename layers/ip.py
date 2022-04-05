from ctypes import c_ubyte, c_uint16, c_uint32, c_uint8
from socket import AF_INET, AF_INET6, inet_ntop
from .Protocol import Protocol

class IPv4(Protocol):
    _fields_ = [
        ("version",c_uint8),   # Protocol version
        ("ihl",c_uint8),       # Internetheader length
        ("dscp",c_uint8),      # Differentiated serices code point
        ("ecp", c_uint8),       # Explicit congestion notification
        ("len", c_uint16),         # Total packet length
        ("id", c_uint16),          # Identification
        ("flags", c_uint16),    # Fragmentation control flags
        ("offset", c_uint16),  # Fragment offset
        ("ttl", c_uint8),          # Time to live
        ("proto", c_uint8),        # Encapsulated protocol
        ("chksum", c_uint16),      # Header checksum
        ("src", c_ubyte * 4),      # Source address
        ("dst", c_ubyte * 4)       # Destination address
    ]
    header_len = 20
    entertypes = {
        0: "IPv6 hop-by-hop options",
        1: "ICMP",
        2: "IGMP",
        3: "gateway-gateway protocol",
        4: "IP in IP",
        5: "ST datagram mode",
        6: "TCP",
        7: "CBT",
        8: "exterior gateway protocol",
        9: "interior gateway protocol",
        10: "BBN RCC monitoring",
        11: "Network Voice Protocol",
        12: "PARC universal packet",
        13: "ARGUS",
        14: "EMCON",
        15: "Cross Net Debugger",
        16: "Chaos",
        17: "UDP",
        18: "multiplexing",
        19: "DCN measurement",
        20: "Host Monitoring Protocol",
        21: "Packet Radio Measurement",
        22: "Xerox NS IDP",
        23: "Trunk-1",
        24: "Trunk-2",
        25: "Leaf-1",
        26: "Leaf-2",
        27: "Reliable Datagram proto",
        28: "Inet Reliable Transaction",
        29: "ISO TP class 4",
        30: "Bulk Data Transfer",
        31: "MFE Network Services",
        32: "Merit Internodal Protocol",
        33: "Sequential Exchange proto",
        34: "Third Party Connect proto",
        35: "Interdomain Policy Route",
        36: "Xpress Transfer Protocol",
        37: "Datagram Delivery Proto",
        38: "IDPR Ctrl Message Trans",
        39: "TP++ Transport Protocol",
        40: "IL Transport Protocol",
        41: "IPv6",
        42: "Source Demand Routing",
        43: "IPv6 routing header",
        44: "IPv6 fragmentation header",
        46: "Reservation protocol",
        47: "General Routing Encap",
        48: "Mobile Host Routing",
        49: "ENA",
        50: "Encap Security Payload",
        51: "Authentication Header",
        52: "Integated Net Layer Sec",
        53: "SWIPE",
        54: "NBMA Address Resolution",
        55: "Mobile IP, RFC 2004",
        56: "Transport Layer Security",
        57: "SKIP",
        58: "ICMP for IPv6",
        59: "IPv6 no next header",
        60: "IPv6 destination options",
        61: "any host internal proto",
        62: "CFTP",
        63: "any local network",
        64: "SATNET and Backroom EXPAK",
        65: "Kryptolan",
        66: "MIT Remote Virtual Disk",
        67: "Inet Pluribus Packet Core",
        68: "any distributed fs",
        69: "SATNET Monitoring",
        70: "VISA Protocol",
        71: "Inet Packet Core Utility",
        72: "Comp Proto Net Executive",
        73: "Comp Protocol Heart Beat",
        74: "Wang Span Network",
        75: "Packet Video Protocol",
        76: "Backroom SATNET Monitor",
        77: "SUN ND Protocol",
        78: "WIDEBAND Monitoring",
        79: "WIDEBAND EXPAK",
        80: "ISO CNLP",
        81: "Versatile Msg Transport",
        82: "Secure VMTP",
        83: "VINES",
        84: "TTP",
        85: "NSFNET-IGP",
        86: "Dissimilar Gateway Proto",
        87: "TCF",
        88: "EIGRP",
        89: "Open Shortest Path First",
        90: "Sprite RPC Protocol",
        91: "Locus Address Resolution",
        92: "Multicast Transport Proto",
        93: "AX.25 Frames",
        94: "yet-another IP encap",
        95: "Mobile Internet Ctrl",
        96: "Semaphore Comm Sec Proto",
        97: "Ethernet in IPv4",
        98: "encapsulation header",
        99: "private encryption scheme",
        100:"GMTP",
        101:"Ipsilon Flow Mgmt Proto",
        102:"PNNI over IP",
        103:"Protocol Indep Multicast",
        104:"ARIS",
        105:"SCPS",
        106:"QNX",
        107:"Active Networks",
        108:"IP Payload Compression",
        109:"Sitara Networks Protocol",
        110:"Compaq Peer Protocol",
        111:"IPX in IP",
        112:"Virtual Router Redundancy",
        113:"PGM Reliable Transport",
        114:"0-hop protocol",
        115:"Layer 2 Tunneling Proto",
        116:"D-II Data Exchange (DDX)",
        117:"Interactive Agent Xfer",
        118:"Schedule Transfer Proto",
        119:"SpectraLink Radio Proto",
        120:"UTI",
        121:"Simple Message Protocol",
        122:"SM",
        123:"Performance Transparency",
        124:"ISIS over IPv4",
        125:"FIRE",
        126:"Combat Radio Transport",
        127:"Combat Radio UDP",
        128:"SSCOPMCE",
        129:"IPLT",
        130:"Secure Packet Shield",
        131:"Private IP Encap in IP",
        132:"Stream Ctrl Transmission",
        133:"Fibre Channel",
        134:"RSVP-E2E-IGNORE",
        255:"Reserved"
    }
    def __init__(self,packet:bytes) -> None:
        super().__init__(packet)
        self.dest = inet_ntop(AF_INET, self.dst)
        self.source = inet_ntop(AF_INET, self.src)
        # 只能识别entertypes中的下层协议
        self.encapsulated_proto = self.entertypes.get(self.proto,None)
        self.info = {
            "dst":self.dest,
            "src":self.source,
            "type":self.encapsulated_proto
        }
        self.header_len = self.ihl

class IPv6(Protocol):
    _fields_ = [
        ("version", c_uint32),   # Protocol version
        ("tclass", c_uint32),    # Traffic class
        ("flabel", c_uint32),   # Flow label
        ("payload_len", c_uint16),  # Payload length
        ("next_header", c_uint8),   # Type of next header
        ("hop_limit", c_uint8),     # Hop limit (replaces IPv4 TTL)
        ("src", c_ubyte * 16),      # Source address
        ("dst", c_ubyte * 16)       # Destination address
    ]
    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.source = inet_ntop(AF_INET6, self.src)
        self.dest = inet_ntop(AF_INET6, self.dst)

        self.info = {
            "dst":self.dest,
            "src":self.source
        }
        self.header_len = 40