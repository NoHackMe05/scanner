from ldap3 import Server, Connection, ALL

from utils.logger import log_debug, log_error

class LDAPScanner:
    def scan(self, host, port=389):
        try:
            server = Server(host, port=port)
            conn = Connection(server, auto_bind=True)

            # Récupérer les informations du serveur
            result = conn.search(search_base="", search_filter="(objectClass=*)", attributes=ALL)

            if result:
                for entry in result:
                    log_debug(f"Entry: {entry}")
                    # Rechercher les attributs contenant des informations sur le serveur (par exemple, motd)
                    if 'motd' in entry['attributes']:
                        return entry['attributes']['motd'][0].decode('utf-8')
            else:
                log_debug(f"No results found for {host}:{port}")

            conn.unbind()
            return
        except Exception as e:
            log_error(f"LDAP scan failed for {host}:{port}: {str(e)}")
            return