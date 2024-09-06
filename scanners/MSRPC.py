import socket

from utils.logger import log_debug, log_error

class MSRPCScanner:
    def scan(self, ip, port=135):
        try:
            # Créer un socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Définir un timeout pour éviter les blocages

            # Tenter de se connecter au port
            result = sock.connect_ex((ip, port))

            if result == 0:
                log_debug(f"Port {port} is opened for {ip}")
                # Envoyer une requête pour récupérer la bannière
                sock.sendall(b'\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xd0\x16\xd0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xca\x5c\x9a\x3b\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00')
                banner = sock.recv(1024)
                return banner
            else:
                log_debug(f"Port {port} is closed for {ip}")
                return
        except socket.error as e:
            log_error(f"MSRPC scan failed for {ip}: {e}")
            return
        finally:
            # Fermer le socket
            sock.close()