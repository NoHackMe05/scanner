import time
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import zmq

from utils.zmqclient import ZMQSnifferClient
from utils.data import DataSniffer
from utils.logger import log_debug, log_info, log_warning, log_error

from scanners.Arp import ArpScanner
from scanners.Nmap import NmapScanner
from scanners.NetBIOS import NetbiosScanner
from scanners.DCFinder import DCFinderScanner
from scanners.FTP import FTPScanner
from scanners.SSH import SSHScanner
from scanners.HTTP import HTTPScanner
from scanners.LDAP import LDAPScanner
from scanners.MSRPC import MSRPCScanner
from scanners.MSDS import MSDSScanner

class NetworkScanner:
    def __init__(self, config):
        self.config = config
        self.data = DataSniffer(config["output_file"])
        self.scanned_ips = set()
        self.lock = threading.Lock()
        self.active_tasks = {"count": 0}
        self.counter_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.sniffer_client = ZMQSnifferClient(config, self.data)

    def check_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                log_debug(f"Un service écoute sur {ip}:{port}")
                return True
            else:
                log_debug(f"Aucun service sur {ip}:{port}")
                return False
        except Exception as e:
            log_error(f"Erreur lors de la vérification de {ip}:{port} - {e}")
            return False
        finally:
            sock.close()

    def agent_connect(self, ip, subnet):
        context = zmq.Context()
        socket = context.socket(zmq.REQ)

        try:
            socket.connect(f"tcp://{ip}:5555")
            log_warning(f"{ip} : Envoi de la commande 'start'...")
            socket.send_string("start")

            timeout = 5000
            poller = zmq.Poller()
            poller.register(socket, zmq.POLLIN)

            socks = dict(poller.poll(timeout))

            if socket in socks and socks[socket] == zmq.POLLIN:
                try:
                    message = socket.recv_json(flags=zmq.NOBLOCK)
                    log_warning(f"{ip} : Réponse reçue de l'agent")
                    self.data.add_infos(ip, subnet, message)
                    return True
                except zmq.Again as e:
                    log_error(f"{ip} : Erreur lors de la lecture du message : {e}")
                    return False
            else:
                log_error(f"{ip} : Timeout atteint : aucune réponse de l'agent.")
                return False
        except zmq.ZMQError as e:
            log_error(f"{ip} : Erreur ZeroMQ lors de la connexion à l'agent : {e}")
            return False
        except Exception as e:
            log_error(f"{ip} : Erreur générale lors de la connexion à l'agent : {e}")
            return False
        finally:
            if 'socket' in locals():
                socket.close()
            if 'context' in locals():
                context.term()

    def launch_scanner(self, scanner_class, ip, subnet, port, *args):
        try:
            log_warning(f"Launching {scanner_class.__name__} for {ip}")
            scanner = scanner_class()
            infos = scanner.scan(*args)
            self.data.add_scanner_infos(ip, subnet, port, infos)
        except Exception as e:
            log_error(f"Error during {scanner_class.__name__} scan for {ip}: {e}")

    def launch_scan(self, ip, subnet):
        if self.stop_event.is_set():
            return

        with self.lock:
            if ip in self.scanned_ips:
                log_info(f"IP {ip} has already been scanned. Skipping.")
                return
            self.scanned_ips.add(ip)

        with self.counter_lock:
            self.active_tasks["count"] += 1

        self.data.host_updated(ip, subnet)

        try:
            if self.check_port(ip, 5555):
                self.agent_connect(ip, subnet)
            else:
                log_warning(f"Launching Nmap for {ip}")
                nmap_scanner = NmapScanner()
                infos = nmap_scanner.scan(ip, self.config["nmap_mode"])
                self.data.add_infos(ip, subnet, infos)

                ports = self.data.get_ip_ports(subnet, ip)
                port_scanner_map = {
                    21: (FTPScanner, [ip]),
                    22: (SSHScanner, [ip]),
                    80: (HTTPScanner, [ip, 80]),
                    135: (MSRPCScanner, [ip, 135]),
                    137: (NetbiosScanner, [ip, 137]),
                    139: (NetbiosScanner, [ip, 139]),
                    389: (LDAPScanner, [ip, 389]),
                    445: (MSDSScanner, [ip, 445]),
                }

                for port in ports:
                    scanner_info = port_scanner_map.get(port)
                    if scanner_info:
                        scanner_class, args = scanner_info
                        self.launch_scanner(scanner_class, ip, subnet, port, *args)
        except Exception as e:
            log_error(f"Error during scan for {ip}: {e}")
            self.data.host_updated(ip, subnet)
        finally:
            with self.counter_lock:
                self.active_tasks["count"] -= 1

    def display_active_tasks(self):
        while not self.stop_event.is_set():
            with self.counter_lock:
                log_info(f"Active tasks: {self.active_tasks['count']}")
            time.sleep(5)

    def start(self):
        log_info("Starting network scanner")

        self.data.load_data(self.config.get("interfaces"))

        self.sniffer_client.connect()

        try:
            threading.Thread(target=self.sniffer_client.listen, daemon=True).start()
            threading.Thread(target=self.display_active_tasks, daemon=True).start()

            with ThreadPoolExecutor(max_workers=self.config.get("max_threads", 4)) as executor:
                while True:
                    subnet_to_scan, interface = self.data.get_subnets_to_scan()

                    if subnet_to_scan and interface:
                        try:
                            log_info(f"Scanning subnet: {subnet_to_scan} on interface: {interface}")
                            arp_scanner = ArpScanner(interface)
                            clients = arp_scanner.scan(subnet_to_scan)

                            for client in clients:
                                self.data.update_mac_for_ip(subnet_to_scan, client["ip"], client["mac"])
                        except Exception as e:
                            log_error(f"Error receiving message: {e}")

                        try:
                            log_info(f"Launching DCFinder for {subnet_to_scan}")
                            ips = self.data.get_ips(subnet_to_scan)
                            dcfinder_scanner = DCFinderScanner()
                            infos = dcfinder_scanner.scan(ips)
                            self.data.add_dc(subnet_to_scan, infos)
                        except Exception as e:
                            log_error(f"Error during DCFinder scan for {subnet_to_scan}: {e}")

                        self.data.subnet_updated(subnet_to_scan)
                    else:
                        log_info("No subnets left to scan.")

                    ip, subnet = self.data.get_host_to_scan()
                    if ip:
                        executor.submit(self.launch_scan, ip, subnet)
                    else:
                        log_info("No IPs left to scan.")

                    time.sleep(self.config.get("scan_interval", 60))
        except KeyboardInterrupt:
            log_error("Stopping sniffer client...")
            self.stop_event.set()
        finally:
            executor.shutdown(wait=True)
            self.data.save_data()
            self.sniffer_client.stop()
