import os
import json
import sys

from utils.network import NetworkScanner
from utils.logger import setup_logger, log_error

def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)
    
def main():
    if os.path.exists("config.json"):
        scanner = NetworkScanner(load_config("config.json"))
        setup_logger(debug_mode=scanner.config.get("debug_mode", False))
    else:
        log_error("No config file")
        sys.exit(0)

    scanner.start()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("CTRL+C pressed. Exiting.")
        sys.exit(0)