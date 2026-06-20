"""
Logging for NmapGUI.
"""

import logging
import os

LOG_DIR = os.path.join(os.path.expanduser("~"), ".local", "share", "nmapgui")
LOG_FILE = os.path.join(LOG_DIR, "nmapgui.log")
SCANS_DIR = os.path.join(os.path.expanduser("~"), "nmapgui-scans")


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(SCANS_DIR, exist_ok=True)

    logger = logging.getLogger("nmapgui")
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(LOG_FILE)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(ch)

    logger.info("NmapGUI started")
    return logger


def get_logger(name="nmapgui"):
    return logging.getLogger(f"nmapgui.{name}")


def get_scans_dir():
    os.makedirs(SCANS_DIR, exist_ok=True)
    return SCANS_DIR
