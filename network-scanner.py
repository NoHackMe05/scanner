import os
import json
import sys
import argparse

from utils.network import NetworkScanner
from utils.logger import setup_logger, log_error

def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)
    
def main():
    # Declare Available arguments
    parser = argparse.ArgumentParser(
        description='Network Scanner')
    parser.add_argument("-c", "--config", help="Config file")

    args = parser.parse_args()

    if args.config:
        config = args.config
    else:
        config = "config2.json"
    
    if os.path.exists(config):
        scanner = NetworkScanner(load_config(config))
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