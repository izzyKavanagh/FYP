import logging
from datetime import datetime

# Create loggers
logging.basicConfig(level=logging.INFO)

allow_logger = logging.getLogger("allowed")
deny_logger = logging.getLogger("denied")

# Handlers write to local log files
allow_handler = logging.FileHandler("allowed.log")
deny_handler = logging.FileHandler("denied.log")

allow_logger.addHandler(allow_handler)
deny_logger.addHandler(deny_handler)

def log_allowed(info):
    allow_logger.info(f"{datetime.now()} ALLOW {info}")

def log_denied(info):
    deny_logger.info(f"{datetime.now()} DROP {info}")