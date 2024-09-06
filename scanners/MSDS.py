import socket

from utils.logger import log_debug, log_error

class MSDSScanner:
    def scan(self, ip, port=445):
        try:
            # Créer un socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Définir un timeout pour éviter les blocages

            # Tenter de se connecter au port
            result = sock.connect_ex((ip, port))

            if result == 0:
                log_debug(f"Port {port} is opened for {ip}")
                # Envoyer une requête pour récupérer la bannière
                sock.sendall(b'\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
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