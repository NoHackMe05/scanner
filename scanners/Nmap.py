import nmap
import threading

class NmapScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan(self, ip, mode="basic"):
        result = {}
        timeout = 120 if mode == "basic" else 240

        def target():
            nonlocal result
            try:
                if mode == "basic":
                    result = self.scanner.scan(ip, arguments=" -T4 -p1-1023,2049,3306,8080 -sV")
                elif mode == "advanced":
                    result = self.scanner.scan(ip, arguments=" -T4 -sV --script banner -p- -sC")
                elif mode == "aggressive":
                    result = self.scanner.scan(ip, arguments=" -T4 -sV --script banner -A")
                else:
                    raise ValueError("Invalid scan mode")
            except nmap.nmap.NmapError as e:
                result = {'error': str(e)}
            except Exception as e:
                result = {'error': f"Unexpected error: {str(e)}"}

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            thread.join()  # Wait for the thread to finish
            result = {'error': 'Scan timed out'}

        return result.get('scan', {'error': 'No scan results'})