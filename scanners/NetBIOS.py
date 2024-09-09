import socket

from utils.logger import log_debug, log_error

class NetbiosScanner:
    def scan(self, ip, port):
        """
        Envoie une requête NetBIOS Name Service (NBT-NS) pour récupérer le nom NetBIOS de l'hôte.
        """
        if port == 137:
            query_packet = b'\x81\x9b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
        elif port == 139:
            query_packet = b'\x81\x00\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
        else:
            query_packet = b'\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4B\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'

        try:
            # Crée une socket UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            sock.sendto(query_packet, (ip, port))

            # Reçoit la réponse
            data, _ = sock.recvfrom(1024)

            # Analyse la réponse pour extraire le nom NetBIOS
            # name = data[57:75].decode('utf-8').strip()
            # log_debug(f"NetBIOS name for {ip}: {name}")

            return data

        except socket.timeout:
            log_error(f"Timeout occurred while querying NetBIOS for {ip}")
            return
        except Exception as e:
            log_error(f"Error occurred while querying NetBIOS for {ip}: {e}")
            return
        finally:
            sock.close()