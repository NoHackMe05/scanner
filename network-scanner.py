import os
import json
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import zmq
import socket

from utils.zmqclient import ZMQSnifferClient
from utils.data import DataSniffer
from utils.logger import setup_logger, log_debug, log_info, log_warning, log_error

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

def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)
    
def check_port(ip, port):
    try:
        # Créer un socket TCP/IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Définir un timeout pour l'opération

        # Tenter de se connecter au serveur
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
    
def agent_connect(ip, subnet, data):
    context = zmq.Context()
    socket = context.socket(zmq.REQ)

    try:
        # Connecte le socket au port de l'agent
        socket.connect(f"tcp://{ip}:5555")

        # Envoie la commande "start"
        log_warning(f"{ip} : Envoi de la commande 'start'...")
        socket.send_string("start")

        timeout = 5000  # Timeout en millisecondes
        poller = zmq.Poller()
        poller.register(socket, zmq.POLLIN)

        # Attente de la réponse avec timeout
        socks = dict(poller.poll(timeout))

        if socket in socks and socks[socket] == zmq.POLLIN:
            # Réception du message si la socket est prête
            try:
                message = socket.recv_json(flags=zmq.NOBLOCK)
                log_warning(f"{ip} : Réponse reçue de l'agent")
                data.add_infos(ip, subnet, message)
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
        # Nettoyage
        if 'socket' in locals():
            socket.close()
        if 'context' in locals():
            context.term()

def launch_scanner(scanner_class, ip, subnet, port, data, *args):
    try:
        log_warning(f"Launching {scanner_class.__name__} for {ip}")
        scanner = scanner_class()
        infos = scanner.scan(*args)
        data.add_scanner_infos(ip, subnet, port, infos)
    except Exception as e:
        log_error(f"Error during {scanner_class.__name__} scan for {ip}: {e}")
        
def launch_scan(ip, subnet, config, data, scanned_ips, lock, active_tasks, counter_lock, stop_event):
    if stop_event.is_set():
        return  # Arrêter le thread si l'événement d'arrêt est défini
    
    with lock:
        if ip in scanned_ips:
            log_info(f"IP {ip} has already been scanned. Skipping.")
            return
        scanned_ips.add(ip)

    with counter_lock:
        active_tasks["count"] += 1  # Incrémenter le compteur de tâches actives

    data.host_updated(ip, subnet)

    try:
        if check_port(ip, 5555):
            agent_connect(ip, subnet, data)
        else:
            log_warning(f"Launching Nmap for {ip}")
            nmap_scanner = NmapScanner()
            infos = nmap_scanner.scan(ip, config["nmap_mode"])
            data.add_infos(ip, subnet, infos)

            ports = data.get_ip_ports(subnet, ip)
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
                    launch_scanner(scanner_class, ip, subnet, port, data, *args)
    except Exception as e:
        log_error(f"Error during scan for {ip}: {e}")
        data.host_updated(ip, subnet)
    finally:
        with counter_lock:
            active_tasks["count"] -= 1  # Décrémenter le compteur de tâches actives       

def display_active_tasks(active_tasks, counter_lock, stop_event):
    while not stop_event.is_set():
        with counter_lock:
            log_info(f"Active tasks: {active_tasks['count']}")
        time.sleep(5)  # Affiche le nombre de tâches toutes les 5 secondes

def main():
    # Configurer le logger
    if os.path.exists("config.json"):
        config = load_config("config.json")
        setup_logger(debug_mode=config.get("debug_mode", False))
    else:
        log_error("No config file")
        sys.exit(0)

    log_info("Starting network scanner")

    # Charger les données initiales
    data = DataSniffer(config["output_file"])
    # data.load_result()
    data.load_data(config.get("interfaces"))

    # **Déclaration de scanned_ips et lock**
    scanned_ips = set()  # Ensemble pour suivre les IPs déjà scannées
    lock = threading.Lock()  # Verrou pour protéger l'accès concurrent à scanned_ips
    active_tasks = {"count": 0}  # Compteur pour les tâches actives
    counter_lock = threading.Lock()  # Verrou pour protéger le compteur de tâches actives
    stop_event = threading.Event()  # Événement pour signaler l'arrêt des threads

    # Créer et démarrer le client ZMQ pour le sniffer
    sniffer_client = ZMQSnifferClient(config, data)
    sniffer_client.connect()

    try:
        # Écouter les messages du sniffer
        threading.Thread(target=sniffer_client.listen, daemon=True).start()

        # Démarrer le thread qui affiche le nombre de tâches actives
        threading.Thread(target=display_active_tasks, args=(active_tasks, counter_lock, stop_event), daemon=True).start()

        # Utiliser ThreadPoolExecutor pour gérer les threads
        with ThreadPoolExecutor(max_workers=config.get("max_threads", 4)) as executor:
            while True:
                # Récupérer les subnets ou les IPs à scanner depuis les données
                subnet_to_scan, interface = data.get_subnets_to_scan()

                if subnet_to_scan and interface:
                    try:
                        log_info(f"Scanning subnet: {subnet_to_scan} on interface: {interface}")
                        arp_scanner = ArpScanner(interface)
                        clients = arp_scanner.scan(subnet_to_scan)

                        for client in clients:
                            data.update_mac_for_ip(subnet_to_scan, client["ip"], client["mac"])
                    except Exception as e:
                        log_error(f"Error receiving message: {e}")
                        pass

                    try:
                        log_info(f"Launching DCFinder for {subnet_to_scan}")
                        ips = data.get_ips(subnet_to_scan)
                        dcfinder_scanner = DCFinderScanner()
                        infos = dcfinder_scanner.scan(ips)
                        data.add_dc(subnet_to_scan, infos)
                    except Exception as e:
                        log_error(f"Error during DCFinder scan for {subnet_to_scan}: {e}")
                        pass

                    data.subnet_updated(subnet_to_scan)
                else:
                    log_info("No subnets left to scan.")

                ip, subnet = data.get_host_to_scan()
                if ip:
                    # Lancer le scan Nmap dans un nouveau thread
                    executor.submit(launch_scan, ip, subnet, config, data, scanned_ips, lock, active_tasks, counter_lock, stop_event)
                else:
                    log_info("No IPs left to scan.")
                
                # Attendre un certain temps avant de refaire le scan
                time.sleep(config.get("scan_interval", 60))
    except KeyboardInterrupt:
        log_error("Stopping sniffer client...")
        stop_event.set()  # Signaler l'arrêt à tous les threads
    finally:
        executor.shutdown(wait=True)  # Attendre la fin de tous les threads
        data.save_data()
        sniffer_client.stop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print ("CTRL+C pressed. Exiting. ")
        sys.exit(0)