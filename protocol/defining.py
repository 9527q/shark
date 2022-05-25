"""一些还没有具体实现的协议"""
from protocol.base import Protocol


class Ieee802_3(Protocol):
    TYPE_NAME = "IEEE 802.3"


class Rarp(Protocol):
    """RARP"""


class Lldp(Protocol):
    """LLDP"""
