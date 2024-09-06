from ftplib import FTP

from utils.logger import log_error

class FTPScanner:
    def scan(self, ip):
        try:
            ftp = FTP(ip)
            ftp.login()
            return ftp.getwelcome()
        except Exception as e:
            log_error(f"Error occurred while querying FTP for {ip}: {e}")
            return
        finally:
            ftp.quit()