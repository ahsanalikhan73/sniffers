#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
import scapy.all as scapy
import argparse
from colorama import init, Fore		# for fancy/colorful display

class DNS_Sniffer:
    def __init__(self):
        # initialize colorama
        init()
        # define colors
        self.GREEN = Fore.GREEN
        self.RED = Fore.RED
        self.Cyan = Fore.CYAN
        self.RESET = Fore.RESET

    def arguments(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-i', '--interface', dest='interface', help='Specify The Interface')
        value = parser.parse_args()
        if not value.interface:
            parser.error(f'\n\n{self.RED}[-] Please Specify The Interface{self.RESET}')
        return value

    def sniff(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_packets, filter='port 53')

    def process_packets(self, packet):
        if packet.haslayer(scapy.DNS):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            print(f'{src_ip}  ==>  {dst_ip} : {self.GREEN}{packet[scapy.DNSQR].qname}{self.RESET}')

    def start(self):
        option = self.arguments()   # capture arguments
        subprocess.call(['clear'])
        print(f'{self.Cyan}\n\n\t\t\t\t\t#########################################################{self.RESET}')
        print(f'\n{self.Cyan}\t\t\t\t\t#\t\t   DNS Packet Sniffer\t\t\t#\n{self.Cyan}')
        print(f'{self.Cyan}\t\t\t\t\t#########################################################{self.RESET}\n\n')

        self.sniff(option.interface)    # start sniffing


if __name__ == "__main__":
    my_sniffer = DNS_Sniffer()
    my_sniffer.start()