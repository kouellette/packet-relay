from scapy.packet import Raw, Packet
from scapy.layers.l2 import Ether, CookedLinux, Loopback
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

# Common EtherTypes for IP/IPv6/ARP
COMMON_ETHER_TYPES = { 0x0800, 0x86DD, 0x0806 }

def parse_frame(data: bytes) -> Packet:
    # 1) Raw IP or IPv6 on loopback-like sources
    if _looks_like_ipv4(data):
        pkt = IP(data)
        if getattr(pkt, "version", None) == 4:
            return pkt
    if _looks_like_ipv6(data):
        pkt = IPv6(data)
        if getattr(pkt, "version", None) == 6:
            return pkt

    # 2) BSD Loopback (DLT_NULL)
    pkt = Loopback(data)
    if _valid_loopback(pkt):
        return pkt

    # 3) Linux Cooked (SLL)
    pkt = CookedLinux(data)
    if _valid_sll(pkt):
        return pkt

    # 4) Ethernet
    pkt = Ether(data)
    if _valid_ether(pkt):
        return pkt

    # 5) Fallback
    return Raw(data)


def _looks_like_ipv4(data: bytes) -> bool:
    if len(data) < 20:
        # IPv4 header is at least 20 bytes.
        return False
    if (data[0] >> 4) != 4:
        # Version field (bits 0-3) must be 4 for IPv4.
        return False

    # IHL field (bits 4-7) is the length of the IPv4 header represented in 32-bit (4-byte) words.
    # IHL min value is 5 (5 * 4 = 20 bytes) and max is 15 (15 * 4 = 60 bytes).
    ihl = data[0] & 0x0F
    if ihl < 5 or ihl > 15:
        return False

    return True

def _looks_like_ipv6(data: bytes) -> bool:
    if len(data) < 40:
        # IPv6 header is at least 40 bytes.
        return False

    # IPv6 version field (bits 0-3) must be 6.
    return (data[0] >> 4) == 6

# On BSD, NullLoopback will have an AF_INET value of 2 for IPv4. IPv6 can have various values depending on the flavor
# of BSD. Values from https://wiki.wireshark.org/NullLoopback
AF_INET_VALS = [2]
AF_INET6_VALS = [24, 28, 30]

def _valid_loopback(pkt: Packet) -> bool:
    # Expect 4-byte type then an inner IP/IPv6 packet
    fam = getattr(pkt, "type", None)
    if fam not in AF_INET_VALS + AF_INET6_VALS:
        return False

    # Check that the packet contains an IP or IPv6 layer
    return bool(pkt.haslayer(IP) or pkt.haslayer(IPv6))

def _valid_sll(pkt: Packet) -> bool:
    proto = getattr(pkt, "proto", None)
    if proto not in COMMON_ETHER_TYPES:
        return False

    return bool(pkt.haslayer(IP) or pkt.haslayer(IPv6))

def _valid_ether(pkt: Packet) -> bool:
    et = getattr(pkt, "type", None)
    # Typical EtherTypes; allow 802.3 length field as a fallback
    if et is None:
        return False

    if et in COMMON_ETHER_TYPES:
        return bool(pkt.haslayer(IP) or pkt.haslayer(IPv6))

    return False
