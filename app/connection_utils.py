"""
Connection utilities for detecting and managing device connections.

Provides port scanning and connection type detection for Cambium devices.
"""
import socket
import logging

logger = logging.getLogger(__name__)


def detect_connection_type(host: str, timeout: int = 2) -> str:
    """
    Detect if device uses SSH or Telnet by checking open ports.

    Args:
        host: Device IP address
        timeout: Port check timeout in seconds

    Returns:
        'ssh' if port 22 is open
        'telnet' if port 23 is open
        'unknown' if neither port is open or detection fails
    """
    # Check SSH port (22) first - most common
    if is_port_open(host, 22, timeout):
        logger.debug(f"{host} has SSH port (22) open")
        return 'ssh'

    # Check Telnet port (23) - used by PMP450
    if is_port_open(host, 23, timeout):
        logger.debug(f"{host} has Telnet port (23) open")
        return 'telnet'

    logger.warning(f"{host} - neither SSH nor Telnet port is open (or detection failed)")
    return 'unknown'


def is_port_open(host: str, port: int, timeout: int = 2) -> bool:
    """
    Check if a TCP port is open on the host.

    Args:
        host: Device IP address
        port: Port number to check
        timeout: Connection timeout in seconds

    Returns:
        True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except socket.error as e:
        logger.debug(f"Socket error checking port {port} on {host}: {e}")
        return False
    except Exception as e:
        logger.warning(f"Unexpected error checking port {port} on {host}: {e}")
        return False