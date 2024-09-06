import os
import json
import ipaddress

from utils.logger import log_info
from requests.structures import CaseInsensitiveDict

class DataSniffer:
    def __init__(self, data_file=""):
        self.data_file = data_file
        self.network_data = {}

    def load_result(self):
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as json_file:
                self.network_data = json.load(json_file)
                return True
        else:
            self.network_data = {"networks": [], "ips": []}
            return False

    def load_data(self, data):
        for item in data:
            item.update({"hosts": [], "vlans": [], "scanned": False, "DC": []})
        self.network_data = {"networks": data, "ips": []}

    def save_data(self):
        # Convertir CaseInsensitiveDict en dictionnaire standard
        def convert_case_insensitive_dict(obj):
            if isinstance(obj, CaseInsensitiveDict):
                return dict(obj)  # Convertir en dictionnaire standard
            elif isinstance(obj, dict):
                return {k: convert_case_insensitive_dict(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_case_insensitive_dict(i) for i in obj]
            else:
                return obj
            
        self.network_data = convert_case_insensitive_dict(self.network_data)
        
        with open(self.data_file, 'w') as json_file:
            json.dump(self.network_data, json_file, indent=4)

    def find_network(self, subnet):
        for network in self.network_data["networks"]:
            if network["subnet"] == subnet:
                return network
        return None
    
    def update_mac_for_ip(self, subnet, ip, mac):
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                for host in network.get('hosts', []):
                    if host['ip'] == ip:
                        host['mac'] = mac
                        host['infos'] = ''
                        host['scanned'] = False
                        return
                # Si l'IP n'existe pas encore, l'ajouter
                network['hosts'].append({'ip': ip, 'mac': mac, 'infos': '', 'scanned': False})
                return
            
    def update_vlan(self, subnet, vlan):
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                if vlan is not None and isinstance(vlan, int) and vlan > 0 and vlan not in network["vlans"]:
                    network["vlans"].append(vlan)
                return
            
    def is_private_ip(self, ip_address):
        ip = ipaddress.ip_address(ip_address)

        # Vérifie si l'adresse IP appartient à l'une des plages privées
        private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16')
        ]

        for network in private_ranges:
            if ip in network:
                return True

        return False
    
    def add_ip_to_network(self, interface, ip, mac='', vlan=''):
        subnet_mask = '255.255.255.0'

        ip_address = ipaddress.ip_address(ip)

        if self.is_private_ip(ip_address):
            subnet = ipaddress.ip_network(f'{ip_address}/{subnet_mask}', strict=False)

            network = self.find_network(str(subnet))
            if not network:
                network = {"subnet": str(subnet), "interface": str(interface), "hosts": [], "vlans": [], "scanned": False}

                if ip not in network["hosts"]:
                    network['hosts'].append({'ip': ip, 'mac': mac, 'infos': '', 'scanned': False})
                    network["scanned"] = False

                if vlan is not None and isinstance(vlan, int) and vlan > 0 and vlan not in network["vlans"]:
                        network["vlans"].append(vlan)

                self.network_data["networks"].append(network)
        else:
            if ip not in self.network_data["ips"]:
                log_info(f"New IP Public find : {ip}")
                self.network_data["ips"].append(ip)

    def get_subnets_to_scan(self):
        for network in self.network_data.get("networks", []):
            if not network.get("scanned", True):
                return network.get("subnet"), network.get("interface")
        return None, None
    
    def subnet_updated(self, subnet):
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                network["scanned"] = True
                return          
        return
    
    def get_host_to_scan(self):
        for network in self.network_data.get("networks", []):
            for host in network.get('hosts', []):
                if not host.get("scanned", True):
                    return host.get("ip"), network.get("subnet")
        return None, None
    
    def host_updated(self, ip, subnet):
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                for host in network.get('hosts', []):
                    if host['ip'] == ip:
                        host["scanned"] = True
                        return                   
        return
    
    def add_infos(self, ip, subnet, infos):
        try:
            if infos[ip] is not None:
                infos = infos[ip]
        except Exception as e:
            pass

        if "addresses" in infos:
            infos.pop("addresses")
        if "status" in infos:
            infos.pop("status")

        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                for host in network.get('hosts', []):
                    if host['ip'] == ip:
                        host["infos"] = infos
                        host["scanner"] = None
                        host['scanned'] = True
                        return                   
        return
    
    def get_ips(self, subnet):
        ips = []
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                for host in network.get('hosts', []):
                    ips.append(host['ip'])

        return ips
    
    def add_dc(self, subnet, ips):
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                network['DC'] = ips
                return
            
        return
    
    def get_ip_ports(self, subnet, ip):
        ports = []
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                for host in network.get('hosts', []):
                    if host['ip'] == ip:
                        tcp_ports = host.get("infos", {}).get("tcp", {})
                        for port, tmp in tcp_ports.items():
                            ports.append(port)

        return ports
    
    def add_scanner_infos(self, ip, subnet, port, infos):
        for network in self.network_data.get('networks', []):
            if network['subnet'] == subnet:
                for host in network.get('hosts', []):
                    if host['ip'] == ip:
                        tcp_ports = host.get("infos", {}).get("tcp", {})
                        for host_port, tmp in tcp_ports.items():
                            if host_port == port:
                                log_info(tcp_ports[host_port])
                                tcp_ports[host_port]["scanner"] = infos
                                return                   
        return