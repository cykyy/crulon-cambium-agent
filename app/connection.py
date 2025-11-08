"""
Connection abstraction layer for Cambium devices.

Provides unified interface for connecting to devices via SSH or Telnet
with automatic protocol detection based on open ports.
"""
import logging
from typing import Tuple, Union
from contextlib import contextmanager
import paramiko
import telnetlib

from app.connection_utils import detect_connection_type
from app.services import ssh_client, telnet_client
from app.config import ROUTER_USER, ROUTER_PASS

logger = logging.getLogger(__name__)


@contextmanager
def connect_to_device(host: str, username: str = None, password: str = None):
    """
    Connect to device using SSH or Telnet based on port detection.

    Strategy:
    1. Port scan to detect SSH (22) or Telnet (23)
    2. If SSH port detected, use SSH connection
    3. If Telnet port detected, use Telnet connection
    4. If neither detected, try SSH first, then Telnet fallback

    Args:
        host: Device IP address
        username: SSH/Telnet username (defaults to ROUTER_USER)
        password: SSH/Telnet password (defaults to ROUTER_PASS)

    Yields:
        Tuple[client, connection_type]: (paramiko.SSHClient or telnetlib.Telnet, 'ssh' or 'telnet')

    Raises:
        RuntimeError: If both SSH and Telnet connections fail
    """
    username = username or ROUTER_USER
    password = password or ROUTER_PASS

    # Detect connection type via port scanning
    conn_type = detect_connection_type(host, timeout=2)

    # Try detected connection type first
    if conn_type == 'ssh':
        try:
            with ssh_client(host, username, password) as client:
                yield client, 'ssh'
                return
        except Exception as e:
            logger.debug(f"SSH connection failed despite port 22 being open: {e}")
            # Fall through to Telnet attempt

    elif conn_type == 'telnet':
        try:
            with telnet_client(host, username, password) as client:
                yield client, 'telnet'
                return
        except Exception as e:
            logger.debug(f"Telnet connection failed despite port 23 being open: {e}")
            # Fall through to SSH attempt

    # Port detection failed or detected connection didn't work - try SSH first (most common)
    try:
        with ssh_client(host, username, password) as client:
            yield client, 'ssh'
            return
    except Exception as ssh_error:
        logger.debug(f"SSH connection failed: {ssh_error}")

        # SSH failed, try Telnet as last resort
        try:
            with telnet_client(host, username, password) as client:
                yield client, 'telnet'
                return
        except Exception as telnet_error:
            logger.error(f"Failed to connect to {host} via both SSH and Telnet")
            raise RuntimeError(
                f"Failed to connect to {host} via both SSH and Telnet. "
                f"SSH error: {ssh_error}. Telnet error: {telnet_error}"
            )


@contextmanager
def connect_direct(host: str, connection_type: str, username: str = None, password: str = None):
    """
    Connect to device using ONLY the specified connection type.

    No port detection, no fallback to alternative connection type.
    Used when model parameter specifies the connection type.

    Args:
        host: Device IP address
        connection_type: 'ssh' or 'telnet' (exact, required)
        username: Username (defaults to ROUTER_USER)
        password: Password (defaults to ROUTER_PASS)

    Yields:
        client: Connected SSH or Telnet client

    Raises:
        RuntimeError: If connection fails
    """
    username = username or ROUTER_USER
    password = password or ROUTER_PASS

    if connection_type == 'ssh':
        with ssh_client(host, username, password) as client:
            yield client
    elif connection_type == 'telnet':
        with telnet_client(host, username, password) as client:
            yield client
    else:
        raise ValueError(f"Invalid connection type: {connection_type}. Must be 'ssh' or 'telnet'")


def run_command(client: Union[paramiko.SSHClient, telnetlib.Telnet],
                cmd: str,
                connection_type: str,
                timeout: int = 30) -> Tuple[str, str]:
    """
    Execute command on device regardless of connection type.

    Args:
        client: SSH or Telnet client
        cmd: Command to execute
        connection_type: 'ssh' or 'telnet'
        timeout: Command timeout in seconds

    Returns:
        Tuple[stdout, stderr]: Command output and errors

    Raises:
        RuntimeError: If command execution fails
    """
    if connection_type == 'ssh':
        return _run_ssh_command(client, cmd, timeout)
    elif connection_type == 'telnet':
        return _run_telnet_command(client, cmd, timeout)
    else:
        raise ValueError(f"Unknown connection type: {connection_type}")


def _run_ssh_command(client: paramiko.SSHClient, cmd: str, timeout: int) -> Tuple[str, str]:
    """Execute command via SSH."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    return out, err


def _run_telnet_command(client: telnetlib.Telnet, cmd: str, timeout: int) -> Tuple[str, str]:
    """
    Execute command via Telnet.

    PMP450 Telnet format:
    - Send command with newline
    - Read until next prompt "Telnet+>"
    - Return output (no stderr for Telnet)
    """
    try:
        # Send command
        client.write(cmd.encode('ascii') + b"\n")

        # Read until next prompt (PMP450 uses "Telnet+>")
        output = client.read_until(b"Telnet+>", timeout=timeout)

        # Decode and clean up output
        output_str = output.decode('ascii', errors='replace')

        # Parse output and remove prompt
        # NOTE: PMP450 Telnet does NOT echo commands, so first line is always data
        lines = output_str.split('\n')

        # Remove last line if it contains the prompt
        if lines and 'Telnet+>' in lines[-1]:
            lines = lines[:-1]

        # Join all remaining lines (including first line - it's data, not echo)
        output_clean = '\n'.join(lines)

        # Clean up carriage returns and whitespace
        output_clean = output_clean.replace('\r', '').strip()

        # Telnet doesn't have stderr, return empty string
        return output_clean, ""

    except EOFError as e:
        logger.error(f"Telnet connection closed during command execution: {e}")
        raise RuntimeError(f"Telnet command failed: connection closed")
    except Exception as e:
        logger.error(f"Telnet command '{cmd}' failed: {e}")
        raise RuntimeError(f"Telnet command failed: {e}")