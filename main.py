import mmap
from datetime import datetime
from struct import unpack
from typing import Callable

from protocol.arp import Arp
from protocol.dns import Dns
from protocol.ip import Ipv4
from protocol.pcap import Pcap
from utils.convert import ipv42str, mac2str
from utils.debug import show_run_time


@show_run_time
def parse_pcap(
    pcap_mm: mmap.mmap,
    arp_write: Callable,
    ip_write: Callable,
    udp_write: Callable,
    dns_write: Callable,
):
    unpack_tag = Pcap.gen_unpack_tag(pcap_mm[:4]) + "L"
    index = 24
    total_len = pcap_mm.size()

    while index < total_len:
        index_30 = index + 30
        header = pcap_mm[index:index_30]
        tp = header[28:30]
        cap_len = unpack(unpack_tag, header[8:12])[0]

        # IPv4
        if tp == b"\x08\x00":
            ts = unpack(unpack_tag, header[:4])[0]
            dest_mac = header[16:22]
            source_mac = header[22:28]

            ipv4 = Ipv4(pcap_mm, index_30)
            ip_str = (
                f"[{datetime.fromtimestamp(ts)}] {cap_len}Bytes"
                f" {mac2str(source_mac)} {mac2str(dest_mac)}"
                f" IPv4 {ipv42str(ipv4.source_ip)} {ipv42str(ipv4.destination_ip)}\n"
            )
            ip_write(ip_str)

            # UDP
            if ipv4.header[9] == 17:
                udp_offset = ipv4.offset + ipv4.HEADER_LEN
                source_port, dest_port = unpack(
                    ">HH", pcap_mm[udp_offset : udp_offset + 4]
                )
                udp_str = f"{ip_str[:-1]} {source_port} {dest_port}\n"
                udp_write(udp_str)

                # DNS
                if source_port == 53 or dest_port == 53:
                    dns = Dns(pcap_mm, udp_offset + 8)
                    dns_write(f"{udp_str[:-1]} {dns.show()}\n")

        # ARP
        elif tp == b"\x08\x06":
            ts = unpack(unpack_tag, header[:4])[0]
            dest_mac = header[16:22]
            source_mac = header[22:28]

            arp = Arp(pcap_mm[index_30 : index + 16 + cap_len])
            arp_write(
                f"[{datetime.fromtimestamp(ts)}] {cap_len}Bytes"
                f" {mac2str(source_mac)} {mac2str(dest_mac)} {arp.show()}\n"
            )

        index += cap_len + 16


if __name__ == "__main__":
    pcap_n = "task/data_day_14.pcap"
    with open(pcap_n) as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        with open("arp.txt", "w") as arp_f, open("ip.txt", "w") as ip_f:
            with open("udp.txt", "w") as udp_f, open("dns.txt", "w") as dns_f:
                parse_pcap(
                    mm,
                    arp_write=arp_f.write,
                    ip_write=ip_f.write,
                    udp_write=udp_f.write,
                    dns_write=dns_f.write,
                )
