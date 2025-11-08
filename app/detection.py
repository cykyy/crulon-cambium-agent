"""
Device detection module for identifying Cambium equipment models.

Uses multiple detection strategies to determine device type and capabilities.
"""
import logging
import re
from typing import Tuple, Union
import paramiko
import telnetlib

from app.device_models import DeviceType

logger = logging.getLogger(__name__)


def run_cmd_safe(client: Union[paramiko.SSHClient, telnetlib.Telnet], cmd: str, connection_type: str, timeout: int = 5) -> Tuple[str, str]:
    """
    Run command and return (stdout, stderr). Never raises exceptions.

    Args:
        client: SSH or Telnet client
        cmd: Command to execute
        connection_type: 'ssh' or 'telnet'
        timeout: Command timeout in seconds

    Returns:
        tuple: (stdout, stderr) - empty strings if command fails
    """
    try:
        from app.connection import run_command
        return run_command(client, cmd, connection_type, timeout)
    except Exception as e:
        logger.debug(f"Command '{cmd}' failed: {e}")
        return "", ""


def detect_device_type(client: Union[paramiko.SSHClient, telnetlib.Telnet], connection_type: str = 'ssh') -> DeviceType:
    """
    Auto-detect Cambium device model type.

    Detection strategy:
    0. Try Cambium CLI 'show dashboard' (Force/ePMP/PMP devices with CLI)
    1. Try 'show version' (Force/ePMP/PMP devices with shell)
    2. Try nvram_get for dual-band (cnPilot R195W/R200/R201)
    3. Try nvram_get for single-band (cnPilot R190W)
    4. Check /proc/cpuinfo for chipset hints
    5. Default to UNKNOWN

    Args:
        client: Connected SSH client

    Returns:
        DeviceType: Detected device type
    """
    # Strategy 0: Check for Cambium CLI (Force/ePMP/PMP devices)
    stdout, stderr = run_cmd_safe(client, "show dashboard", connection_type)

    if stdout and "Unknown command" not in stderr and len(stdout) > 500:
        stdout_lower = stdout.lower()

        # Parse dashboard output for device model indicators
        if "f300" in stdout_lower or "force 300" in stdout_lower or "force300" in stdout_lower:
            return DeviceType.FORCE_300

        if "f200" in stdout_lower or "force 200" in stdout_lower or "force200" in stdout_lower:
            return DeviceType.FORCE_200

        if ("pmp" in stdout_lower and "450" in stdout_lower) or "pmp450" in stdout_lower:
            return DeviceType.PMP_450

        if "epmp" in stdout_lower:
            return DeviceType.FORCE_200

        # Valid dashboard output but can't identify specific model
        if "cambium" in stdout_lower or "device" in stdout_lower:
            return DeviceType.FORCE_300

    # Strategy 0.5: Try PMP450 Telnet commands (version/ver/softversion)
    if connection_type == 'telnet':
        for cmd in ["version", "ver", "softversion"]:
            stdout, stderr = run_cmd_safe(client, cmd, connection_type)
            if stdout and "command not found" not in stdout.lower():
                stdout_lower = stdout.lower()
                # PMP450 uses "CANOPY" as its software platform name
                if "canopy" in stdout_lower or "pmp" in stdout_lower or "point-to-multipoint" in stdout_lower:
                    return DeviceType.PMP_450

    # Strategy 1: Try 'show version' command (Force/ePMP/PMP devices)
    stdout, stderr = run_cmd_safe(client, "show version", connection_type)
    if stdout:
        device_type = _parse_show_version(stdout)
        if device_type != DeviceType.UNKNOWN:
            return device_type

    # Strategy 2: Try dual-band nvram commands (cnPilot R195W, R200, R201)
    stdout, stderr = run_cmd_safe(client, "nvram_get rtdev RTDEV_SSID1", connection_type)
    if stdout and not stderr and "command not found" not in stdout.lower():
        return DeviceType.CNPILOT_DUAL_BAND

    # Strategy 3: Try single-band nvram commands (cnPilot R190W)
    stdout, stderr = run_cmd_safe(client, "nvram_get 2860 SSID1", connection_type)
    if stdout and not stderr and "command not found" not in stdout.lower():
        return DeviceType.CNPILOT_SINGLE_BAND

    # Strategy 4: Check /proc/cpuinfo for chipset hints
    stdout, stderr = run_cmd_safe(client, "cat /proc/cpuinfo", connection_type)
    if stdout:
        if "RT2880" in stdout or "RT2860" in stdout or "Ralink" in stdout:
            return DeviceType.CNPILOT_SINGLE_BAND

    # Strategy 5: Check for common Force/PMP directories or files
    stdout, stderr = run_cmd_safe(client, "ls /usr/www/cambium 2>/dev/null", connection_type)
    if stdout:
        if "force" in stdout.lower() or "epmp" in stdout.lower():
            return DeviceType.FORCE_200

    # Strategy 6: Try additional Force-specific commands
    stdout, stderr = run_cmd_safe(client, "uname -a", connection_type)
    if stdout and ("force" in stdout.lower() or "cambium" in stdout.lower()):
        return DeviceType.FORCE_300

    # Check for Force config files
    stdout, stderr = run_cmd_safe(client, "ls /etc/config 2>/dev/null", connection_type)

    logger.warning("⚠ Could not detect device type - all detection strategies failed")
    logger.warning("This may be a Force/PMP device with different command structure")
    return DeviceType.UNKNOWN


def _parse_show_version(output: str) -> DeviceType:
    """
    Parse 'show version' output to determine device type.

    Expected output format:
    Model: Force 200
    Hardware Version: 1.0
    Software Version: 4.6.1
    ...
    """
    output_lower = output.lower()

    # Check for Force 200
    if "force 200" in output_lower or "force200" in output_lower:
        return DeviceType.FORCE_200

    # Check for Force 300
    if "force 300" in output_lower or "force300" in output_lower:
        return DeviceType.FORCE_300

    # Check for PMP450
    if "pmp 450" in output_lower or "pmp450" in output_lower or "pmp-450" in output_lower:
        return DeviceType.PMP_450

    # Check for ePMP (treat as Force for now)
    if "epmp" in output_lower:
        return DeviceType.FORCE_200

    return DeviceType.UNKNOWN
