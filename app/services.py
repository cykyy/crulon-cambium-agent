import logging
from contextlib import contextmanager
from typing import Dict, Any
import paramiko
import telnetlib

from app.config import (
    ROUTER_USER, ROUTER_PASS,
    COMMAND_TIMEOUT, LOG_LEVEL
)
from app.detection import detect_device_type
from app.device_models import DeviceType
from app.adapters.cnpilot import CnPilotAdapter
from app.adapters.force import ForceAdapter
from app.adapters.pmp450 import PMP450Adapter

# Set up logging with configurable level
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Conditionally enable Paramiko debug logging (only in DEBUG mode)
if LOG_LEVEL == 'DEBUG':
    try:
        paramiko.util.log_to_file('/tmp/paramiko.log')
        logger.info("Paramiko logging enabled at /tmp/paramiko.log")
    except Exception as e:
        logger.warning(f"Could not enable Paramiko file logging: {e}")


@contextmanager
def ssh_client(host: str, username: str, password: str):
    if not password:
        raise RuntimeError("ROUTER_PASS not set in environment (.env) – set ROUTER_PASS before running")
    client = paramiko.SSHClient()
    # Use WarningPolicy for production - logs unknown hosts but allows connection
    # For stricter security, use RejectPolicy and maintain a known_hosts file
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    try:
        client.connect(
            host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
        )
        yield client
    finally:
        client.close()


@contextmanager
def telnet_client(host: str, username: str, password: str):
    """
    Telnet connection context manager for PMP450 and other Telnet-based devices.

    Args:
        host: Device IP address
        username: Telnet username
        password: Telnet password

    Yields:
        telnetlib.Telnet: Connected Telnet client
    """
    if not password:
        raise RuntimeError("ROUTER_PASS not set in environment (.env) – set ROUTER_PASS before running")

    tn = None
    try:
        tn = telnetlib.Telnet(host, port=23, timeout=10)

        # Wait for login prompt
        tn.read_until(b"login: ", timeout=5)
        tn.write(username.encode('ascii') + b"\n")

        # Wait for password prompt
        tn.read_until(b"assword: ", timeout=5)  # Matches both "Password:" and "password:"
        tn.write(password.encode('ascii') + b"\n")

        # Wait for command prompt (PMP450 uses "Telnet+>")
        tn.read_until(b"Telnet+>", timeout=5)

        yield tn

    except EOFError as e:
        logger.error(f"Telnet connection to {host} closed unexpectedly: {e}")
        raise RuntimeError(f"Telnet connection failed: {e}")
    except Exception as e:
        logger.error(f"Telnet connection to {host} failed: {e}")
        raise RuntimeError(f"Telnet connection failed: {e}")
    finally:
        if tn:
            try:
                tn.write(b"exit\n")
            except:
                pass
            try:
                tn.close()
            except:
                pass


def run_cmd(client: paramiko.SSHClient, cmd: str) -> str:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=COMMAND_TIMEOUT)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if err and not out:
        # Some busybox variants write warnings to stderr; be conservative
        raise RuntimeError(f"Command '{cmd}' failed: {err}")
    return out


def create_device_adapter(client, host: str, device_type: DeviceType, connection_type: str = 'ssh'):
    """
    Factory function to create appropriate device adapter.

    Args:
        client: Connected SSH or Telnet client
        host: Device IP address
        device_type: Detected device type
        connection_type: 'ssh' or 'telnet'

    Returns:
        BaseDeviceAdapter: Adapter instance for the device
    """
    if device_type in (DeviceType.CNPILOT_DUAL_BAND, DeviceType.CNPILOT_SINGLE_BAND):
        return CnPilotAdapter(client, host, device_type, connection_type)
    elif device_type in (DeviceType.FORCE_200, DeviceType.FORCE_300):
        return ForceAdapter(client, host, device_type, connection_type)
    elif device_type == DeviceType.PMP_450:
        return PMP450Adapter(client, host, device_type, connection_type)
    elif device_type == DeviceType.UNKNOWN:
        # Gracefully handle unknown devices - try Force adapter as fallback
        logger.warning(f"Unknown device type for {host} - using Force adapter as fallback")
        return ForceAdapter(client, host, DeviceType.FORCE_300, connection_type)
    else:
        raise ValueError(f"Unsupported device type: {device_type}")


def collect_device_info(host: str, model: str = None) -> Dict[str, Any]:
    """
    Connect to device (SSH or Telnet), auto-detect model type, and collect appropriate data.

    Uses port detection to automatically determine SSH vs Telnet connection.

    Args:
        host: IPv4/IPv6 address of device
        model: Optional model hint (e.g., 'pmp_450', 'force_300', 'R195W').
               If specified, skips auto-detection and uses model's connection type directly.
               Falls back to auto-detection if model hint fails.

    Returns:
        dict: Device information with model-appropriate fields
    """
    from app.connection import connect_to_device, connect_direct
    from app.device_models import validate_and_parse_model, DEVICE_CONNECTION_TYPE

    # If model specified, try direct connection with model's connection type
    if model:
        try:
            device_type = validate_and_parse_model(model)
            connection_type = DEVICE_CONNECTION_TYPE[device_type]

            # Direct connection (no auto-detection)
            with connect_direct(host, connection_type, ROUTER_USER, ROUTER_PASS) as client:
                adapter = create_device_adapter(client, host, device_type, connection_type)
                return adapter.get_device_info()

        except Exception as e:
            logger.debug(f"Model hint '{model}' failed: {e}. Falling back to auto-detection")
            # Fall through to auto-detection

    # Auto-detection flow (no model hint or model hint failed)
    with connect_to_device(host, ROUTER_USER, ROUTER_PASS) as (client, connection_type):
        # Auto-detect device type
        device_type = detect_device_type(client, connection_type)

        # Create appropriate adapter and collect device info
        adapter = create_device_adapter(client, host, device_type, connection_type)
        return adapter.get_device_info()


def collect_router_info(host: str, model: str = None) -> Dict[str, Any]:
    """
    DEPRECATED: Use collect_device_info() instead.

    Maintained for backward compatibility. Calls collect_device_info internally.

    Args:
        host: IPv4/IPv6 address of device
        model: Optional model hint (passed through to collect_device_info)

    Returns:
        dict: Device information
    """
    return collect_device_info(host, model)
