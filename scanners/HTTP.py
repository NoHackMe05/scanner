import requests

from utils.logger import log_error

class HTTPScanner:
    def scan(self, host, port):
        try:
            response = requests.get(f"http://{host}:{port}", timeout=5)
            return response.headers
        except requests.exceptions.RequestException as e:
            log_error(f"HTTP scan failed for {host}:{port}: {str(e)}")
            return