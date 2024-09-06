import paramiko

from utils.logger import log_error

class SSHScanner:
    def __init__(self, username='user', password='password'):
        self.username = username
        self.password = password

    def scan(self, ip):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=self.username, password=self.password)
            stdin, stdout, stderr = client.exec_command('uname -a')
            return stdout.read().decode()
        except Exception as e:
            log_error(f"Error occurred while querying SSH for {ip}: {e}")
            return
        finally:
            client.close()
