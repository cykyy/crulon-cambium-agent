import os
import logging
from pathlib import Path

# Set up logging for configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    # Optional dependency; if installed we load a local .env file.
    from dotenv import load_dotenv  # type: ignore
    _DOTENV_LOADED = load_dotenv(dotenv_path=Path('.') / '.env')
    logger.info(f"Dotenv loading: {'SUCCESS' if _DOTENV_LOADED else 'SKIPPED (no .env file or failed)'}")
except Exception as e:  # pragma: no cover - non-critical
    _DOTENV_LOADED = False
    logger.warning(f"Dotenv loading failed: {e}")

# Router SSH credentials
ROUTER_USER = os.getenv("ROUTER_USER")
ROUTER_PASS = os.getenv("ROUTER_PASS")

# API authentication token
API_TOKEN = os.getenv("API_TOKEN")

# Logging level configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING").upper()

# Debug mode (enables debug endpoints like /debug/env-check)
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

# Validate critical configuration
if not ROUTER_PASS:
    logger.error("ROUTER_PASS is not set! SSH connections will fail.")

# Server configuration
PORT = int(os.getenv("PORT", "8000"))

# NVRAM keys for SSID
SSID_24_CMD = "nvram_get 2860 SSID1"
SSID_5_CMD = "nvram_get rtdev RTDEV_SSID1"

# NVRAM keys for WPA PSK (passwords)
PASS_24_CMD = "nvram_get 2860 WPAPSK1"
PASS_5_CMD = "nvram_get rtdev RTDEV_WPAPSK1"

# Router commands
ARP_CMD = "arp -n"
UPTIME_CMD = "uptime"

# SSH timeouts
COMMAND_TIMEOUT = 5
SSH_CONNECTION_TIMEOUT = 8
