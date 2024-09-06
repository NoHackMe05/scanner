from scapy.all import ARP, Ether, srp

class ArpScanner:
    def __init__(self, interface="eth0"):
        self.interface = interface

    def scan(self, ip_range):
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, iface=self.interface, verbose=False)[0]
        
        clients = []
        for sent, received in answered_list:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        
        return clients
