"""
Adapter for Cambium PMP450 series point-to-multipoint equipment.

PMP450 devices are wireless base stations or subscriber modules.
NOT WiFi routers - provides link status and metrics.
"""
import time
import logging
import re
from typing import Dict, Any

from app.adapters.base import BaseDeviceAdapter
from app.device_models import DeviceType, get_device_config
from app.utils import parse_uptime

logger = logging.getLogger(__name__)


class PMP450Adapter(BaseDeviceAdapter):
    """Adapter for PMP450 point-to-multipoint devices."""

    def __init__(self, client, host: str, device_type: DeviceType, connection_type: str = 'telnet'):
        """
        Initialize PMP450 adapter.

        Args:
            client: Telnet or SSH client (PMP450 typically uses Telnet)
            host: Device IP
            device_type: PMP_450
            connection_type: 'telnet' or 'ssh' (defaults to 'telnet' for PMP450)
        """
        super().__init__(client, host, connection_type)
        self.device_type = device_type
        self.capabilities, self.commands, self.interface_map = get_device_config(device_type)

    def get_device_info(self) -> Dict[str, Any]:
        """
        Collect comprehensive PMP450 device information via Telnet.

        Returns basic device status (advanced CLI commands not available via Telnet).
        """
        # Get uptime (works via Telnet)
        uptime_raw, stderr = self.run_cmd_safe(self.commands.uptime_cmd)
        uptime = parse_uptime(uptime_raw) if uptime_raw else {
            "raw": "",
            "uptime_human": None,
            "uptime_seconds": None
        }

        # Get device version info (for additional context)
        version_raw, _ = self.run_cmd_safe(self.commands.model_detect_cmd)

        # Note: Advanced link metrics not available via Telnet
        # PMP450 Telnet CLI doesn't support 'show wireless', 'show rssi', etc.
        link_info = {
            "status": "unknown",
            "signal_strength": None,
            "link_quality": None,
            "throughput": None,
        }

        return {
            "timestamp": int(time.time()),
            "router": self.host,
            "device_type": self.device_type.value,
            "capabilities": {
                "has_wifi": self.capabilities.has_wifi,
                "dual_band": self.capabilities.dual_band,
                "has_clients": self.capabilities.has_clients,
                "has_bridge_mode": self.capabilities.has_bridge_mode,
                "has_link_metrics": False,  # Not available via Telnet
                "can_reboot": self.capabilities.can_reboot,
            },
            "ssid_2g": None,  # Not applicable for PMP equipment
            "ssid_5g": None,
            "password_2g": None,
            "password_5g": None,
            "uptime": uptime,
            "link_status": link_info.get("status"),
            "signal_strength": link_info.get("signal_strength"),
            "link_quality": link_info.get("link_quality"),
            "throughput": link_info.get("throughput"),
            "clients": [],  # PMP devices don't have WiFi clients
            "_raw": {
                "uptime": uptime_raw,
                "version": version_raw,
            },
            "notes": [
                "PMP450 connected via Telnet",
                "Advanced link metrics not available via Telnet CLI",
                "Use web interface or SNMP for detailed statistics"
            ]
        }

    def get_uptime(self) -> Dict[str, Any]:
        """Get device uptime."""
        uptime_raw, _ = self.run_cmd_safe(self.commands.uptime_cmd)
        if uptime_raw:
            return parse_uptime(uptime_raw)
        return {
            "raw": "",
            "uptime_human": None,
            "uptime_seconds": None
        }

    def get_wifi_credentials(self) -> Dict[str, Any]:
        """
        WiFi credentials not applicable for PMP equipment.

        Returns None for all fields.
        """
        return {
            "ssid_2g": None,
            "ssid_5g": None,
            "password_2g": None,
            "password_5g": None,
        }

    def get_network_clients(self) -> list:
        """
        PMP devices don't have WiFi clients.

        Returns empty list (use link_status instead).
        """
        return []

    def update_wifi_credentials(self, ssid: str = None, password: str = None) -> bool:
        """
        WiFi credential updates not supported on PMP equipment.

        Returns False.
        """
        logger.warning("WiFi credential updates not supported on PMP450 devices")
        return False

    def reboot(self) -> bool:
        """Reboot the device."""
        try:
            self.run_cmd(self.commands.reboot_cmd)
            return True
        except Exception as e:
            logger.error(f"Failed to reboot device: {e}")
            return False

    def _get_wireless_status(self) -> Dict[str, Any]:
        """
        Get wireless link status and metrics.

        Returns:
            dict: Wireless status, signal strength, quality, throughput
        """
        result = {
            "status": "unknown",
            "signal_strength": None,
            "link_quality": None,
            "throughput": None,
            "raw": ""
        }

        if not self.commands.link_status_cmd:
            return result

        stdout, stderr = self.run_cmd_safe(self.commands.link_status_cmd)
        result["raw"] = stdout

        if not stdout:
            result["status"] = "down"
            return result

        # Parse 'show wireless' output
        # This is a placeholder - actual parsing depends on PMP450 output format
        # User will need to test with actual device and update parsing logic
        try:
            # Check link status
            if "registered" in stdout.lower() or "synchronized" in stdout.lower():
                result["status"] = "up"
            elif "scanning" in stdout.lower() or "not registered" in stdout.lower():
                result["status"] = "down"
            else:
                result["status"] = "unknown"

            # Try to extract signal strength
            signal_match = re.search(r"(?:signal|rssi)[:\s]+(-?\d+)\s*dBm", stdout, re.IGNORECASE)
            if signal_match:
                result["signal_strength"] = int(signal_match.group(1))

            # Try to extract link quality/SNR
            snr_match = re.search(r"snr[:\s]+(\d+)", stdout, re.IGNORECASE)
            if snr_match:
                result["link_quality"] = int(snr_match.group(1))

        except Exception as e:
            logger.warning(f"Failed to parse wireless status: {e}")

        return result
