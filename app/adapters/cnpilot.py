"""
Adapter for Cambium cnPilot home router series.

Supports: R190W (single-band), R195W/R200/R201 (dual-band)
"""
import time
import logging
from typing import Dict, Any

from app.adapters.base import BaseDeviceAdapter
from app.device_models import DeviceType, get_device_config
from app.utils import (
    parse_arp, parse_dumpleases, parse_brctl_show,
    parse_brctl_showmacs, parse_uptime, assemble_clients
)

logger = logging.getLogger(__name__)


class CnPilotAdapter(BaseDeviceAdapter):
    """Adapter for cnPilot home routers using NVRAM configuration."""

    def __init__(self, client, host: str, device_type: DeviceType, connection_type: str = 'ssh'):
        """
        Initialize cnPilot adapter.

        Args:
            client: SSH or Telnet client
            host: Device IP
            device_type: CNPILOT_DUAL_BAND or CNPILOT_SINGLE_BAND
            connection_type: 'ssh' or 'telnet'
        """
        super().__init__(client, host, connection_type)
        self.device_type = device_type
        self.capabilities, self.commands, self.interface_map = get_device_config(device_type)

    def get_device_info(self) -> Dict[str, Any]:
        """
        Collect comprehensive cnPilot router information.

        Returns complete data structure matching original collect_router_info().
        """
        # Get WiFi credentials
        ssid_24 = self.run_cmd(self.commands.ssid_2g_cmd)

        ssid_5 = None
        pass_5 = None
        if self.capabilities.dual_band:
            try:
                ssid_5 = self.run_cmd(self.commands.ssid_5g_cmd)
            except Exception as e:
                logger.warning(f"Could not get 5GHz SSID: {e}")

        # Get passwords
        try:
            pass_24 = self.run_cmd(self.commands.password_2g_cmd)
        except Exception:
            pass_24 = None

        if self.capabilities.dual_band:
            try:
                pass_5 = self.run_cmd(self.commands.password_5g_cmd)
            except Exception:
                pass_5 = None

        # Get system info
        uptime_raw = self.run_cmd(self.commands.uptime_cmd)
        arp_raw = self.run_cmd(self.commands.arp_cmd)

        # Get DHCP leases
        try:
            leases_raw = self.run_cmd('dumpleases -f /var/udhcpd.leases')
        except Exception:
            leases_raw = ''

        # Get bridge info
        try:
            br_raw = self.run_cmd('brctl show')
        except Exception:
            br_raw = ''

        try:
            brmacs_raw = self.run_cmd('brctl showmacs br0')
        except Exception:
            brmacs_raw = ''

        # Get /proc/net/arp
        try:
            proc_arp_raw = self.run_cmd('cat /proc/net/arp')
        except Exception:
            proc_arp_raw = ''

        # Get wireless config
        try:
            iw_raw = self.run_cmd('iwconfig')
        except Exception:
            iw_raw = ''

        # Parse data
        arp_clients = parse_arp(arp_raw)
        leases = parse_dumpleases(leases_raw)
        br_ifaces = parse_brctl_show(br_raw, bridge='br0')
        br_mac_map = parse_brctl_showmacs(brmacs_raw)

        # Parse /proc/net/arp
        proc_arp_clients = []
        if proc_arp_raw:
            for line in proc_arp_raw.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    proc_arp_clients.append({
                        'ip': parts[0],
                        'mac': parts[3],
                        'interface': parts[5]
                    })

        # Merge ARP sources
        if proc_arp_clients:
            mac_index = {c['mac'].lower(): c for c in arp_clients}
            for p in proc_arp_clients:
                mac = p['mac'].lower()
                if mac in mac_index:
                    mac_index[mac]['ip'] = p['ip']
                    mac_index[mac]['interface'] = p['interface']
                else:
                    arp_clients.append(p)

        # Assemble clients with interface mapping
        clients = assemble_clients(
            leases, br_ifaces, br_mac_map, arp_clients,
            interface_map=self.interface_map
        )
        uptime = parse_uptime(uptime_raw)

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
            "ssid_2g": ssid_24,
            "ssid_5g": ssid_5,
            "password_2g": pass_24,
            "password_5g": pass_5,
            "uptime": uptime,
            "clients": clients,
            "_raw": {
                'arp': arp_raw,
                'proc_arp': proc_arp_raw,
                'leases': leases_raw,
                'brctl': br_raw,
                'brctl_showmacs': brmacs_raw,
                'iwconfig': iw_raw,
            }
        }

    def get_uptime(self) -> Dict[str, Any]:
        """Get device uptime."""
        uptime_raw = self.run_cmd(self.commands.uptime_cmd)
        return parse_uptime(uptime_raw)

    def get_wifi_credentials(self) -> Dict[str, Any]:
        """Get WiFi SSIDs and passwords."""
        result = {
            "ssid_2g": None,
            "ssid_5g": None,
            "password_2g": None,
            "password_5g": None,
        }

        try:
            result["ssid_2g"] = self.run_cmd(self.commands.ssid_2g_cmd)
        except Exception as e:
            logger.warning(f"Could not get 2.4GHz SSID: {e}")

        if self.capabilities.dual_band:
            try:
                result["ssid_5g"] = self.run_cmd(self.commands.ssid_5g_cmd)
            except Exception as e:
                logger.warning(f"Could not get 5GHz SSID: {e}")

        try:
            result["password_2g"] = self.run_cmd(self.commands.password_2g_cmd)
        except Exception:
            pass

        if self.capabilities.dual_band:
            try:
                result["password_5g"] = self.run_cmd(self.commands.password_5g_cmd)
            except Exception:
                pass

        return result

    def get_network_clients(self) -> list:
        """Get list of connected WiFi clients."""
        # Get ARP table
        arp_raw = self.run_cmd(self.commands.arp_cmd)
        arp_clients = parse_arp(arp_raw)

        # Get DHCP leases
        try:
            leases_raw = self.run_cmd('dumpleases -f /var/udhcpd.leases')
            leases = parse_dumpleases(leases_raw)
        except Exception:
            leases = []

        # Get bridge info
        try:
            br_raw = self.run_cmd('brctl show')
            br_ifaces = parse_brctl_show(br_raw, bridge='br0')
        except Exception:
            br_ifaces = {}

        try:
            brmacs_raw = self.run_cmd('brctl showmacs br0')
            br_mac_map = parse_brctl_showmacs(brmacs_raw)
        except Exception:
            br_mac_map = {}

        return assemble_clients(
            leases, br_ifaces, br_mac_map, arp_clients,
            interface_map=self.interface_map
        )

    def update_wifi_credentials(self, ssid: str = None, password: str = None) -> bool:
        """
        Update WiFi SSID and/or password.

        Args:
            ssid: New SSID (will append "_2.4 Ghzs" and "_5 Ghzs")
            password: New password

        Returns:
            bool: True if successful
        """
        try:
            if ssid:
                ssid_24 = f"{ssid}_2.4 Ghzs"
                self.run_cmd(f'{self.commands.set_ssid_2g_cmd} "{ssid_24}"')

                if self.capabilities.dual_band:
                    ssid_5 = f"{ssid}_5 Ghzs"
                    self.run_cmd(f'{self.commands.set_ssid_5g_cmd} "{ssid_5}"')

            if password:
                self.run_cmd(f'{self.commands.set_password_2g_cmd} "{password}"')

                if self.capabilities.dual_band:
                    self.run_cmd(f'{self.commands.set_password_5g_cmd} "{password}"')

            return True
        except Exception as e:
            logger.error(f"Failed to update WiFi credentials: {e}")
            return False

    def reboot(self) -> bool:
        """Reboot the device."""
        try:
            self.run_cmd(self.commands.reboot_cmd)
            return True
        except Exception as e:
            logger.error(f"Failed to reboot device: {e}")
            return False
