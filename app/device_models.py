"""
Device model registry for Cambium equipment.

Defines capabilities, commands, and detection patterns for each supported model.
"""
from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass


class DeviceType(str, Enum):
    """Supported Cambium device types."""
    CNPILOT_DUAL_BAND = "cnpilot_dual_band"  # R195W, R200, R201
    CNPILOT_SINGLE_BAND = "cnpilot_single_band"  # R190W
    FORCE_200 = "force_200"
    FORCE_300 = "force_300"
    PMP_450 = "pmp_450"
    UNKNOWN = "unknown"


@dataclass
class DeviceCapabilities:
    """Defines what a device can do."""
    has_wifi: bool  # Can provide WiFi SSIDs and passwords
    dual_band: bool  # Has both 2.4GHz and 5GHz
    has_clients: bool  # Can list connected WiFi clients
    has_bridge_mode: bool  # Operates as wireless bridge
    has_link_metrics: bool  # Can provide link quality metrics
    can_reboot: bool  # Supports reboot command


@dataclass
class CommandSet:
    """Device-specific command mappings."""
    # WiFi credentials
    ssid_2g_cmd: Optional[str] = None
    ssid_5g_cmd: Optional[str] = None
    password_2g_cmd: Optional[str] = None
    password_5g_cmd: Optional[str] = None

    # WiFi credential updates
    set_ssid_2g_cmd: Optional[str] = None
    set_ssid_5g_cmd: Optional[str] = None
    set_password_2g_cmd: Optional[str] = None
    set_password_5g_cmd: Optional[str] = None

    # System info
    uptime_cmd: str = "uptime"
    reboot_cmd: str = "reboot"
    model_detect_cmd: Optional[str] = None

    # Network info
    arp_cmd: str = "arp -n"
    interface_cmd: str = "iwconfig"

    # Bridge/link specific (basic)
    link_status_cmd: Optional[str] = None
    signal_strength_cmd: Optional[str] = None

    # Cambium CLI commands (Force/PMP devices)
    wireless_stats_cmd: Optional[str] = None  # Detailed wireless statistics
    rssi_cmd: Optional[str] = None  # RSSI by channel
    ip_config_cmd: Optional[str] = None  # IP addresses, netmask, gateway
    ethernet_stats_cmd: Optional[str] = None  # Ethernet port statistics
    arp_table_cmd: Optional[str] = None  # ARP table
    sta_list_cmd: Optional[str] = None  # Connected stations (AP mode)
    ap_list_cmd: Optional[str] = None  # Available APs (SM mode)
    syslog_cmd: Optional[str] = None  # System logs


@dataclass
class InterfaceMapping:
    """Maps interface names to logical types."""
    wifi_2g: List[str]
    wifi_5g: List[str]
    wifi_guest: List[str]
    wired: List[str]
    bridge: List[str]


# Device Model Registry
DEVICE_MODELS: Dict[DeviceType, tuple] = {
    DeviceType.CNPILOT_DUAL_BAND: (
        DeviceCapabilities(
            has_wifi=True,
            dual_band=True,
            has_clients=True,
            has_bridge_mode=False,
            has_link_metrics=False,
            can_reboot=True,
        ),
        CommandSet(
            ssid_2g_cmd="nvram_get 2860 SSID1",
            ssid_5g_cmd="nvram_get rtdev RTDEV_SSID1",
            password_2g_cmd="nvram_get 2860 WPAPSK1",
            password_5g_cmd="nvram_get rtdev RTDEV_WPAPSK1",
            set_ssid_2g_cmd="nvram_set 2860 SSID1",
            set_ssid_5g_cmd="nvram_set rtdev RTDEV_SSID1",
            set_password_2g_cmd="nvram_set 2860 WPAPSK1",
            set_password_5g_cmd="nvram_set rtdev RTDEV_WPAPSK1",
            model_detect_cmd="nvram_get 2860 HostName",
        ),
        InterfaceMapping(
            wifi_2g=["ra0", "wds0"],
            wifi_5g=["rai0", "wdsi0"],
            wifi_guest=["ra1"],
            wired=["eth0", "eth1", "eth2", "eth3"],
            bridge=["br0"],
        ),
    ),

    DeviceType.CNPILOT_SINGLE_BAND: (
        DeviceCapabilities(
            has_wifi=True,
            dual_band=False,
            has_clients=True,
            has_bridge_mode=False,
            has_link_metrics=False,
            can_reboot=True,
        ),
        CommandSet(
            ssid_2g_cmd="nvram_get 2860 SSID1",
            password_2g_cmd="nvram_get 2860 WPAPSK1",
            set_ssid_2g_cmd="nvram_set 2860 SSID1",
            set_password_2g_cmd="nvram_set 2860 WPAPSK1",
            model_detect_cmd="nvram_get 2860 HostName",
        ),
        InterfaceMapping(
            wifi_2g=["ra0", "wds0"],
            wifi_5g=[],
            wifi_guest=["ra1"],
            wired=["eth0", "eth1", "eth2", "eth3"],
            bridge=["br0"],
        ),
    ),

    DeviceType.FORCE_200: (
        DeviceCapabilities(
            has_wifi=False,
            dual_band=False,
            has_clients=False,
            has_bridge_mode=True,
            has_link_metrics=True,
            can_reboot=True,
        ),
        CommandSet(
            model_detect_cmd="show dashboard",
            link_status_cmd="show dashboard",
            signal_strength_cmd="show rssi",  # More accurate than dashboard
            reboot_cmd="reboot",
            # Cambium CLI commands
            wireless_stats_cmd="show wireless",
            rssi_cmd="show rssi",
            ip_config_cmd="show ip",
            ethernet_stats_cmd="show ethernet",
            arp_table_cmd="show arp",
            sta_list_cmd="show sta",  # For AP mode
            ap_list_cmd="show ap",  # For SM mode
            syslog_cmd="show syslog",
        ),
        InterfaceMapping(
            wifi_2g=[],
            wifi_5g=[],
            wifi_guest=[],
            wired=["eth0"],
            bridge=["br0"],
        ),
    ),

    DeviceType.FORCE_300: (
        DeviceCapabilities(
            has_wifi=False,
            dual_band=False,
            has_clients=False,
            has_bridge_mode=True,
            has_link_metrics=True,
            can_reboot=True,
        ),
        CommandSet(
            model_detect_cmd="show dashboard",
            link_status_cmd="show dashboard",
            signal_strength_cmd="show rssi",  # More accurate than dashboard
            reboot_cmd="reboot",
            # Cambium CLI commands
            wireless_stats_cmd="show wireless",
            rssi_cmd="show rssi",
            ip_config_cmd="show ip",
            ethernet_stats_cmd="show ethernet",
            arp_table_cmd="show arp",
            sta_list_cmd="show sta",  # For AP mode
            ap_list_cmd="show ap",  # For SM mode
            syslog_cmd="show syslog",
        ),
        InterfaceMapping(
            wifi_2g=[],
            wifi_5g=[],
            wifi_guest=[],
            wired=["eth0"],
            bridge=["br0"],
        ),
    ),

    DeviceType.PMP_450: (
        DeviceCapabilities(
            has_wifi=False,
            dual_band=False,
            has_clients=False,
            has_bridge_mode=True,
            has_link_metrics=True,
            can_reboot=True,
        ),
        CommandSet(
            # PMP450 Telnet commands (NOT Cambium CLI)
            model_detect_cmd="version",  # Use 'version' not 'show dashboard'
            uptime_cmd="uptime",  # Standard command that works
            reboot_cmd="reboot",  # Standard reboot command
            syslog_cmd="syslog",  # Use 'syslog' not 'show syslog'
            # Advanced CLI commands not available via Telnet - set to None
            link_status_cmd=None,
            signal_strength_cmd=None,
            wireless_stats_cmd=None,
            rssi_cmd=None,
            ip_config_cmd=None,
            ethernet_stats_cmd=None,
            arp_table_cmd=None,
            sta_list_cmd=None,
            ap_list_cmd=None,
        ),
        InterfaceMapping(
            wifi_2g=[],
            wifi_5g=[],
            wifi_guest=[],
            wired=["eth0"],
            bridge=["br0"],
        ),
    ),
}


def get_device_config(device_type: DeviceType) -> tuple:
    """
    Get device configuration (capabilities, commands, interface mapping).

    Returns:
        tuple: (DeviceCapabilities, CommandSet, InterfaceMapping)
    """
    return DEVICE_MODELS.get(device_type, (
        DeviceCapabilities(
            has_wifi=False,
            dual_band=False,
            has_clients=False,
            has_bridge_mode=False,
            has_link_metrics=False,
            can_reboot=False,
        ),
        CommandSet(),
        InterfaceMapping(
            wifi_2g=[], wifi_5g=[], wifi_guest=[], wired=[], bridge=[]
        ),
    ))


def map_interface_to_type(interface: str, mapping: InterfaceMapping) -> str:
    """Map network interface name to logical type."""
    if interface in mapping.wifi_2g:
        return "wifi_2.4ghz"
    if interface in mapping.wifi_5g:
        return "wifi_5ghz"
    if interface in mapping.wifi_guest:
        return "wifi_guest"
    if interface in mapping.bridge:
        return "bridge"
    if interface.startswith("eth") or interface in mapping.wired:
        return "wired"
    return "unknown_or_idle"


# Device connection type mapping
DEVICE_CONNECTION_TYPE: Dict[DeviceType, str] = {
    DeviceType.PMP_450: "telnet",
    DeviceType.FORCE_200: "ssh",
    DeviceType.FORCE_300: "ssh",
    DeviceType.CNPILOT_DUAL_BAND: "ssh",
    DeviceType.CNPILOT_SINGLE_BAND: "ssh",
}


def validate_and_parse_model(model_str: str) -> DeviceType:
    """
    Validate and parse model string to DeviceType enum.

    Accepts:
    - Exact enum values (case-insensitive): "cnpilot_dual_band", "force_300", "pmp_450", etc.
    - Friendly names (case-insensitive): "R195W", "R200", "Force 300", "PMP450", etc.
    - Pattern-based matching: "pmp450d sm/5ghz", "REG-PL-R195W", "force 300", etc.

    Args:
        model_str: Model name from user input

    Returns:
        DeviceType: Parsed device type enum

    Raises:
        ValueError: If model string is invalid or UNKNOWN
    """
    # Normalize input
    normalized = model_str.lower().strip().replace(" ", "").replace("-", "").replace("_", "")

    # Try exact enum value match (case-insensitive)
    for device_type in DeviceType:
        if device_type == DeviceType.UNKNOWN:
            continue  # Don't allow UNKNOWN as input
        enum_normalized = device_type.value.lower().replace("_", "")
        if normalized == enum_normalized:
            return device_type

    # Try friendly name mapping
    friendly_map = {
        # cnPilot dual-band models
        "r195w": DeviceType.CNPILOT_DUAL_BAND,
        "r200": DeviceType.CNPILOT_DUAL_BAND,
        "r201": DeviceType.CNPILOT_DUAL_BAND,
        "cnpilotr195w": DeviceType.CNPILOT_DUAL_BAND,
        "cnpilotr200": DeviceType.CNPILOT_DUAL_BAND,
        "cnpilotr201": DeviceType.CNPILOT_DUAL_BAND,

        # cnPilot single-band models
        "r190w": DeviceType.CNPILOT_SINGLE_BAND,
        "cnpilotr190w": DeviceType.CNPILOT_SINGLE_BAND,

        # Force models
        "force200": DeviceType.FORCE_200,
        "force300": DeviceType.FORCE_300,

        # PMP450 models
        "pmp450": DeviceType.PMP_450,
        "pmp": DeviceType.PMP_450,
    }

    if normalized in friendly_map:
        return friendly_map[normalized]

    # Try pattern-based matching (most flexible)
    # Check for device type indicators in the normalized string
    # Order matters: check more specific patterns first

    # Force devices (check specific models first)
    if "force300" in normalized:
        return DeviceType.FORCE_300
    if "force200" in normalized:
        return DeviceType.FORCE_200

    # PMP450 devices (all variants)
    if "pmp450" in normalized or (normalized.startswith("pmp") and len(normalized) <= 6):
        return DeviceType.PMP_450

    # cnPilot devices
    if "r195w" in normalized:
        return DeviceType.CNPILOT_DUAL_BAND
    if "r200" in normalized:
        return DeviceType.CNPILOT_DUAL_BAND
    if "r201" in normalized:
        return DeviceType.CNPILOT_DUAL_BAND
    if "r190w" in normalized:
        return DeviceType.CNPILOT_SINGLE_BAND

    # Invalid model
    valid_models = [e.value for e in DeviceType if e != DeviceType.UNKNOWN]
    raise ValueError(
        f"Invalid model '{model_str}'. Valid models: {', '.join(valid_models)}"
    )
