import enum
from enum import Enum

from utils.classes import Getitem
from utils.convert import ip2str


@enum.unique
class IpUpType(Enum):
    """IP 协议上层协议"""

    RESERVED = 0  # 保留Reserved
    ICMP = 1  # ICMP, Internet Control Message [RFC792]
    IGMP = 2  # IGMP, Internet Group Management [RFC1112]
    GGP = 3  # GGP, Gateway-to-Gateway [RFC823]
    IP_IN_IP = 4  # IP in IP (encapsulation) [RFC2003]
    TCP = 6  # TCP Transmission Control Protocol [RFC793]
    UDP = 17  # UDP User Datagram Protocol [RFC768]
    HMP = 20  # HMP Host Monitoring Protocol [RFC 869]
    RDP = 27  # RDP Reliable Data Protocol [ RFC908 ]
    RSVP = 46  # RSVP (Reservation Protocol)
    GRE = 47  # GRE (General Routing Encapsulation)
    ESP = 50  # ESP Encap Security Payload [RFC2406]
    AH = 51  # AH (Authentication Header) [RFC2402]
    NARP = 54  # NARP (NBMA Address Resolution Protocol) [RFC1735]
    IPV6_ICMP = 58  # IPv6-ICMP (ICMP for IPv6) [RFC1883]
    IPV6_NONXT = 59  # IPv6-NoNxt (No Next Header for IPv6) [RFC1883]
    IPV6_OPTS = 60  # IPv6-Opts (Destination Options for IPv6) [RFC1883]
    OSPF = 89  # OSPF (OSPF Version 2) [RFC 1583]
    VRRP = 112  # VRRP (Virtual Router Redundancy Protocol) [RFC3768]
    L2TP = 115  # L2TP (Layer Two Tunneling Protocol)
    ISIS = 124  # ISIS over IPv4
    CRTP = 126  # CRTP (Combat Radio Transport Protocol)
    CRUDP = 127  # CRUDP (Combat Radio User Protocol)
    SCTP = 132  # SCTP (Stream Control Transmission Protocol)
    UDP_LITE = 136  # UDPLite [RFC 3828]
    MPLS_IN_IP = 137  # MPLS-in-IP [RFC 4023]


class Ipv4(Getitem):
    NAME = "IPv4"

    @property
    def up_type(self):
        return IpUpType(self[9])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.source_ip = self[12:16]
        self.destination_ip = self[16:20]
        self.ttl = self[8]

    def show(self) -> str:
        return (
            f"{ip2str(self.source_ip)}"
            f"  {ip2str(self.destination_ip)}"
            f"  {self.ttl:3}"
            f"  {self.up_type.name}"
        )


class Ipv6(Getitem):
    NAME = "IPv6"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.up_type = None
