import zmq
import threading
import re
import time

from utils.logger import setup_logger, log_debug, log_info, log_error

class ZMQSnifferClient:
    def __init__(self, config, data):
        self.zmq_address = config["sniffer"]["zmq_address"]
        self.zmq_address_pub = config["sniffer"]["zmq_address_pub"]
        self.filter = config["sniffer"]["filter"]
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REQ)  # REQ pour envoyer des commandes et recevoir des réponses
        self.stop_event = threading.Event()
        self.data = data

    def connect(self):
        # Se connecter au sniffer via ZMQ
        self.socket.connect(self.zmq_address)
        log_info(f"Connected to ZMQ sniffer at {self.zmq_address}")

    def send_command(self, command):
        log_info(f"Sending command: {command}")
        try:
            self.socket.send_string(command)
            message = self.socket.recv_string()  # Recevoir la réponse du serveur
            log_info(f"Received reply: {message}")
        except zmq.ZMQError as e:
            log_error(f"Error sending command or receiving reply: {e}")
            pass

    def listen(self):
        # Envoyer la commande de démarrage
        self.send_command("start")

        # Mise en place du filtre
        self.send_command(self.filter)

        # Utiliser un socket PUB/SUB pour écouter les messages
        sub_socket = self.context.socket(zmq.SUB)
        sub_socket.connect(self.zmq_address_pub)
        sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")  # S'abonner à tous les messages

        while not self.stop_event.is_set():
            try:
                message = sub_socket.recv_string(flags=zmq.NOBLOCK)
                log_debug(f"Received message: {message}")
                self.process_message(message, self.data)
            except zmq.Again:
                time.sleep(1)  # Attendre un court moment avant de réessayer
            except Exception as e:
                log_error(f"Error receiving message: {e}")
                break

    def process_message(self, message, data):
        # Utilisation d'une expression régulière pour extraire IPs et VLAN
        pattern = r"Interface:\s*(\S+),\s*IP:\s*([\d\.]+)\s*/\s*([\da-f:]+)\s*->\s*([\d\.]+)\s*/\s*([\da-f:]+),\s*VLAN:\s*(\d+)"
        match = re.match(pattern, message)
        if match:
            interface, src_ip, src_mac, dst_ip, dst_mac, vlan = match.groups()
            vlan = None if vlan == 0 else vlan

            log_debug(f"Interface {interface}, Source IP: {src_ip}, Destination IP: {dst_ip}, VLAN: {vlan}")

            self.data.add_ip_to_network(interface, src_ip, src_mac, None)
            self.data.add_ip_to_network(interface, dst_ip, dst_mac, vlan)
        else:
            log_error(f"Message format incorrect: {message}")

    def launch_scan(self, ip):
        # Implémentez ici le lancement du scan, par exemple avec nmap
        log_debug(f"Launching scan for IP: {ip}")
        # Exécution d'une commande nmap (exemple)
        # subprocess.run(["nmap", "-sV", ip])

    def stop(self):
        self.send_command("stop")
        self.stop_event.set()
        self.socket.close()
        self.context.term()