import scapy.all as scapy
import socket
from colorama import Fore, Style, init

init(autoreset=True)

def get_hostname(ip):
    """محاولة الحصول على اسم الجهاز من خلال الـ IP"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan(ip_range):
    print(f"\n{Fore.CYAN}[*] جاري فحص الشبكة: {ip_range} ...\n")
    
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    print(f"{Fore.YELLOW}{'IP Address':<15} {'MAC Address':<20} {'Hostname':<20}")
    print("-" * 60)

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        hostname = get_hostname(ip)
        
        print(f"{Fore.GREEN}{ip:<15} {Fore.WHITE}{mac:<20} {Fore.BLUE}{hostname:<20}")

target_ip = "192.168.1.1/24" 
scan(target_ip)
