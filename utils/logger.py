import logging

def setup_logger(debug_mode=False):
    level = logging.DEBUG if debug_mode else logging.INFO
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=level)

def log_debug(message):
    green_color = '\033[92m'
    reset_color = '\033[0m'
    logging.debug(f"{green_color}{message}{reset_color}")

def log_info(message):
    cyan_color = '\033[96m'
    reset_color = '\033[0m'
    logging.info(f"{cyan_color}{message}{reset_color}")

def log_warning(message):
    yellow_color = '\033[93m'
    reset_color = '\033[0m'
    logging.warning(f"{yellow_color}{message}{reset_color}")

def log_error(message):
    red_color = '\033[31m'
    reset_color = '\033[0m'
    logging.error(f"{red_color}{message}{reset_color}")
