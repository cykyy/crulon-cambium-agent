"""
Base device adapter interface.

Defines the contract that all device adapters must implement.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Union
import logging
import paramiko
import telnetlib

logger = logging.getLogger(__name__)


class BaseDeviceAdapter(ABC):
    """
    Abstract base class for device adapters.

    Each device type (cnPilot, Force, PMP) implements this interface
    to provide device-specific data collection logic.
    """

    def __init__(self, client: Union[paramiko.SSHClient, telnetlib.Telnet], host: str, connection_type: str = 'ssh'):
        """
        Initialize adapter with SSH or Telnet client.

        Args:
            client: Connected SSH or Telnet client
            host: Device IP address
            connection_type: 'ssh' or 'telnet'
        """
        self.client = client
        self.host = host
        self.connection_type = connection_type

    @abstractmethod
    def get_device_info(self) -> Dict[str, Any]:
        """
        Collect comprehensive device information.

        Returns:
            dict: Complete device data including all available metrics
        """
        pass

    @abstractmethod
    def get_uptime(self) -> Dict[str, Any]:
        """
        Get device uptime information.

        Returns:
            dict: {'raw': str, 'uptime_human': str, 'uptime_seconds': int}
        """
        pass

    @abstractmethod
    def get_wifi_credentials(self) -> Dict[str, Any]:
        """
        Get WiFi SSID and password information.

        Returns:
            dict: {'ssid_2g': str, 'ssid_5g': str, 'password_2g': str, 'password_5g': str}
                  Returns None for fields not supported by device
        """
        pass

    @abstractmethod
    def get_network_clients(self) -> list:
        """
        Get list of connected clients/devices.

        Returns:
            list: List of client dictionaries with MAC, IP, hostname, etc.
        """
        pass

    @abstractmethod
    def update_wifi_credentials(self, ssid: str = None, password: str = None) -> bool:
        """
        Update WiFi SSID and/or password.

        Args:
            ssid: New SSID (optional)
            password: New password (optional)

        Returns:
            bool: True if successful, False otherwise
        """
        pass

    @abstractmethod
    def reboot(self) -> bool:
        """
        Reboot the device.

        Returns:
            bool: True if reboot command sent successfully
        """
        pass

    def run_cmd(self, cmd: str, timeout: int = 5) -> str:
        """
        Execute command on device via SSH or Telnet.

        Args:
            cmd: Command to execute
            timeout: Command timeout in seconds

        Returns:
            str: Command output (stdout)

        Raises:
            RuntimeError: If command fails with stderr and no stdout
        """
        from app.connection import run_command

        out, err = run_command(self.client, cmd, self.connection_type, timeout)
        if err and not out:
            raise RuntimeError(f"Command '{cmd}' failed: {err}")
        return out

    def run_cmd_safe(self, cmd: str, timeout: int = 5) -> tuple:
        """
        Execute command and return both stdout and stderr without raising.

        Args:
            cmd: Command to execute
            timeout: Command timeout in seconds

        Returns:
            tuple: (stdout, stderr)
        """
        try:
            from app.connection import run_command
            return run_command(self.client, cmd, self.connection_type, timeout)
        except Exception as e:
            logger.warning(f"Command '{cmd}' failed on {self.host} ({self.connection_type}): {e}")
            return "", ""
