import socket
from ldap3 import Server, Connection, ALL

from utils.logger import log_debug, log_info, log_error

class DCFinderScanner:
    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return True
            else:
                return False
        except Exception as e:
            log_error(f"Error: {e}")
            return False
        finally:
            sock.close()

    def scan(self, ip_range):
        ips = []
        for ip in ip_range:
            try:
                if self.scan_port(ip, 3268):
                    log_debug(f"Port 3268 is open on {ip}. Attempting to connect to DCFinder service...")
                    try:
                        server = Server(ip, port=3268, get_info=ALL)
                        conn = Connection(server, auto_bind=True)
                        if conn.bind():
                            log_info(f"Successfully connected to DCFinder service on {ip}:3268")
                            log_info(f"Server info: {server.info}")
                            ips.append(ip)
                        else:
                            log_info(f"Failed to bind to DCFinder service on {ip}:3268")
                    except Exception as e:
                        log_error(f"Error: {e}")
                        pass
                elif self.scan_port(ip, 389):
                    log_debug(f"Port 389 is open on {ip}. Attempting to connect to DCFinder service...")
                    try:
                        # Essayer de se connecter au port LDAP (389)
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(1)
                        result = s.connect_ex((ip, 389))
                        if result == 0:
                            log_info(f"Possible DC found: {ip}")

                            # Essayer une requête LDAP simple
                            server = Server(ip, port=389)
                            conn = Connection(server)
                            conn.bind()
                            if conn.bound:
                                log_info(f"Confirmed: LDAP server on {ip}")
                                ips.append(ip)     
                    except Exception as e:
                        log_error(f"Error: {e}")
                        pass
            except Exception as e:
                log_error(f"Error: {e}")
                pass

        return ips
