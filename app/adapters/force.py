"""
Adapter for Cambium Force 200/300 series wireless bridges.

These are point-to-point wireless bridges, NOT WiFi routers.
No SSIDs/passwords - provides link status and metrics instead.
"""
import time
import logging
import re
from typing import Dict, Any

from app.adapters.base import BaseDeviceAdapter
from app.device_models import DeviceType, get_device_config
from app.utils import parse_uptime

logger = logging.getLogger(__name__)


class ForceAdapter(BaseDeviceAdapter):
    """Adapter for Force 200/300 wireless bridges."""

    def __init__(self, client, host: str, device_type: DeviceType, connection_type: str = 'ssh'):
        """
        Initialize Force adapter.

        Args:
            client: SSH or Telnet client
            host: Device IP
            device_type: FORCE_200 or FORCE_300
            connection_type: 'ssh' or 'telnet'
        """
        super().__init__(client, host, connection_type)
        self.device_type = device_type
        self.capabilities, self.commands, self.interface_map = get_device_config(device_type)

    def get_device_info(self) -> Dict[str, Any]:
        """
        Collect comprehensive Force device information using Cambium CLI.

        Returns device status and link metrics (no WiFi data).
        """
        # Get uptime (using get_uptime which handles CLI fallback)
        uptime = self.get_uptime()

        # Get link status (uses show dashboard + show rssi + show wireless)
        link_info = self._get_link_status()

        # Get network configuration if available
        network_config = None
        if self.commands.ip_config_cmd:
            ip_out, _ = self.run_cmd_safe(self.commands.ip_config_cmd)
            if ip_out and len(ip_out) > 50:
                network_config = {"raw": ip_out[:500]}  # Store for future parsing

        return {
            "timestamp": int(time.time()),
            "router": self.host,
            "device_type": self.device_type.value,
            "capabilities": {
                "has_wifi": self.capabilities.has_wifi,
                "dual_band": self.capabilities.dual_band,
                "has_clients": self.capabilities.has_clients,
                "has_bridge_mode": self.capabilities.has_bridge_mode,
                "has_link_metrics": self.capabilities.has_link_metrics,
                "can_reboot": self.capabilities.can_reboot,
            },
            "ssid_2g": None,  # Not applicable for bridges
            "ssid_5g": None,
            "password_2g": None,
            "password_5g": None,
            "uptime": uptime,
            "link_status": link_info.get("status"),
            "signal_strength": link_info.get("signal_strength"),
            "link_quality": link_info.get("link_quality"),
            "tx_rate_mbps": link_info.get("tx_rate"),
            "rx_rate_mbps": link_info.get("rx_rate"),
            "mcs_uplink": link_info.get("mcs_uplink"),  # MCS mode for TX
            "mcs_downlink": link_info.get("mcs_downlink"),  # MCS mode for RX
            "clients": [],  # Bridges don't have WiFi clients
            "network_config": network_config,
            "_raw": {
                "uptime": uptime.get("raw", ""),
                "dashboard": link_info.get("raw_dashboard", ""),
                "rssi": link_info.get("raw_rssi", ""),
                "wireless": link_info.get("raw_wireless", ""),
            }
        }

    def get_uptime(self) -> Dict[str, Any]:
        """
        Get device uptime.

        Force devices use Cambium CLI - uptime from 'show dashboard'.
        """
        # Try standard uptime command first (may not work in CLI)
        uptime_raw, stderr = self.run_cmd_safe(self.commands.uptime_cmd)

        # If uptime command fails (CLI mode), try to extract from dashboard
        if not uptime_raw or "Unknown command" in stderr:
            dashboard, _ = self.run_cmd_safe("show dashboard")
            if dashboard:
                # Parse uptime from dashboard output
                # Format may vary, look for uptime-related fields
                uptime_seconds = self._parse_uptime_from_dashboard(dashboard)
                if uptime_seconds:
                    return {
                        "raw": f"Uptime: {uptime_seconds} seconds",
                        "uptime_human": self._format_uptime(uptime_seconds),
                        "uptime_seconds": uptime_seconds
                    }

        # Fall back to parse_uptime if we got raw uptime output
        if uptime_raw:
            return parse_uptime(uptime_raw)

        return {
            "raw": "",
            "uptime_human": None,
            "uptime_seconds": None
        }

    def _parse_uptime_from_dashboard(self, dashboard: str) -> int | None:
        """Extract uptime in seconds from dashboard output."""
        # Look for uptime patterns in dashboard
        # Example: "uptime: 1234567" or "System Uptime: X days, Y hours"
        # Cambium format: "cambiumSystemUptime 0015:08:09:04" (DDDD:HH:MM:SS)
        import re

        # Try Cambium format first: cambiumSystemUptime DDDD:HH:MM:SS
        match = re.search(r'cambiumSystemUptime\s+(\d+):(\d+):(\d+):(\d+)', dashboard)
        if match:
            days = int(match.group(1))
            hours = int(match.group(2))
            minutes = int(match.group(3))
            seconds = int(match.group(4))
            total_seconds = (days * 86400) + (hours * 3600) + (minutes * 60) + seconds
            return total_seconds

        # Try to find uptime in seconds
        match = re.search(r'uptime[:\s]+(\d+)', dashboard, re.IGNORECASE)
        if match:
            return int(match.group(1))

        # Try to find days/hours format
        match = re.search(r'(\d+)\s*days?,\s*(\d+)\s*hours?', dashboard, re.IGNORECASE)
        if match:
            days = int(match.group(1))
            hours = int(match.group(2))
            return (days * 86400) + (hours * 3600)

        return None

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime seconds into human-readable string."""
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60

        if days > 0:
            return f"{days} days, {hours}:{minutes:02d}"
        elif hours > 0:
            return f"{hours}:{minutes:02d}"
        else:
            return f"{minutes} min"

    def get_wifi_credentials(self) -> Dict[str, Any]:
        """
        WiFi credentials not applicable for wireless bridges.

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
        Wireless bridges don't have WiFi clients.

        Returns empty list (use link_status instead).
        """
        return []

    def update_wifi_credentials(self, ssid: str = None, password: str = None) -> bool:
        """
        WiFi credential updates not supported on wireless bridges.

        Returns False.
        """
        logger.warning("WiFi credential updates not supported on Force devices (wireless bridges)")
        return False

    def reboot(self) -> bool:
        """Reboot the device."""
        try:
            self.run_cmd(self.commands.reboot_cmd)
            return True
        except Exception as e:
            logger.error(f"Failed to reboot device: {e}")
            return False

    def _get_link_status(self) -> Dict[str, Any]:
        """
        Get wireless link status and metrics from Cambium CLI.

        Uses multiple commands for comprehensive data:
        - show dashboard: Overall status
        - show rssi: Signal strength
        - show wireless: TX/RX rates and stats

        Returns:
            dict: Link status, signal strength, quality, tx/rx rates
        """
        result = {
            "status": "unknown",
            "signal_strength": None,
            "link_quality": None,
            "tx_rate": None,
            "rx_rate": None,
            "mcs_uplink": None,  # TX MCS mode
            "mcs_downlink": None,  # RX MCS mode
            "raw_dashboard": "",
            "raw_rssi": "",
            "raw_wireless": ""
        }

        # Get dashboard output (primary source for link status)
        dashboard_out, _ = self.run_cmd_safe(self.commands.link_status_cmd)
        result["raw_dashboard"] = dashboard_out

        # Get RSSI data (more accurate signal strength)
        if self.commands.rssi_cmd:
            rssi_out, _ = self.run_cmd_safe(self.commands.rssi_cmd)
            result["raw_rssi"] = rssi_out

        # Get wireless stats (TX/RX rates)
        if self.commands.wireless_stats_cmd:
            wireless_out, _ = self.run_cmd_safe(self.commands.wireless_stats_cmd)
            result["raw_wireless"] = wireless_out

        # Parse dashboard for link status
        if dashboard_out and len(dashboard_out) > 100:
            dashboard_lower = dashboard_out.lower()

            # Check link status
            if any(term in dashboard_lower for term in ["connected", "associated", "registered", "synchronized", "link up"]):
                result["status"] = "up"
            elif any(term in dashboard_lower for term in ["disconnected", "not associated", "link down", "searching"]):
                result["status"] = "down"
            elif len(dashboard_out) > 500:  # Got substantial output
                result["status"] = "up"

            # Extract signal from dashboard (fallback if RSSI command fails)
            if not result["signal_strength"]:
                # Try Cambium-specific format first (case-insensitive)
                match = re.search(r'cambiumstadlrssi\s+(-?\d+)', dashboard_lower)
                if match:
                    result["signal_strength"] = int(match.group(1))
                else:
                    # Try generic patterns
                    for pattern in [r"rssi[:\s]+(-?\d+)", r"signal[:\s]+(-?\d+)", r"dl\s+rssi[:\s]+(-?\d+)"]:
                        match = re.search(pattern, dashboard_lower)
                        if match:
                            result["signal_strength"] = int(match.group(1))
                            break

            # Extract SNR/quality from dashboard
            # Try Cambium-specific format first (case-insensitive)
            match = re.search(r'cambiumstadlsnr\s+(\d+)', dashboard_lower)
            if match:
                result["link_quality"] = int(match.group(1))
            else:
                # Try generic patterns
                for pattern in [r"snr[:\s]+(\d+)", r"link\s+quality[:\s]+(\d+)", r"quality[:\s]+(\d+)"]:
                    match = re.search(pattern, dashboard_lower)
                    if match:
                        result["link_quality"] = int(match.group(1))
                        break

            # Extract MCS modes from dashboard
            # Uplink MCS = TX from device perspective
            match = re.search(r'cambiumstauplinkmcsmode\s+(\d+)', dashboard_lower)
            if match:
                result["mcs_uplink"] = int(match.group(1))

            # Downlink MCS = RX from device perspective
            match = re.search(r'cambiumstadownlinkmcsmode\s+(\d+)', dashboard_lower)
            if match:
                result["mcs_downlink"] = int(match.group(1))

        # Parse RSSI output for more accurate signal strength
        if rssi_out and len(rssi_out) > 20:
            rssi_lower = rssi_out.lower()
            # Try to find current RSSI value
            for pattern in [r"rssi[:\s]+(-?\d+)", r"current[:\s]+(-?\d+)", r"signal[:\s]+(-?\d+)"]:
                match = re.search(pattern, rssi_lower)
                if match:
                    result["signal_strength"] = int(match.group(1))
                    break

        # Parse wireless stats for TX/RX rates
        if wireless_out and len(wireless_out) > 50:
            wireless_lower = wireless_out.lower()

            # Try to extract TX rate (in Mbps)
            for pattern in [r"tx\s+rate[:\s]+(\d+)", r"transmit\s+rate[:\s]+(\d+)", r"tx[:\s]+(\d+)\s*mbps"]:
                match = re.search(pattern, wireless_lower)
                if match:
                    result["tx_rate"] = int(match.group(1))
                    break

            # Try to extract RX rate (in Mbps)
            for pattern in [r"rx\s+rate[:\s]+(\d+)", r"receive\s+rate[:\s]+(\d+)", r"rx[:\s]+(\d+)\s*mbps"]:
                match = re.search(pattern, wireless_lower)
                if match:
                    result["rx_rate"] = int(match.group(1))
                    break

        return result
