import re
import ipaddress
from typing import List, Dict, Any, Optional
from fastapi import HTTPException


def validate_ip(ip: str) -> None:
    """Raise HTTPException if the provided ip is not a valid IPv4/IPv6 literal.

    We intentionally disallow hostnames here for clarity/security. Relax if needed.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")


def parse_uptime(raw: str) -> Dict[str, Any]:
    # Example: " 14:12:33 up 5 days,  3:17,  1 user,  load average: 0.00, 0.01, 0.05"
    # Simpler approach: ask router for /proc/uptime? If available: cat /proc/uptime
    # We'll attempt to derive seconds heuristically if /proc/uptime isn't used.
    # Try /proc/uptime first for precision.
    return {
        "raw": raw,
        "uptime_human": extract_human_uptime(raw),
        "uptime_seconds": extract_seconds_from_uptime(raw),
    }


def extract_human_uptime(raw: str) -> str:
    # Check for PMP450 format first: 14d, 23:40:59
    pmp450_match = re.search(r"(\d+)d,\s*(\d+):(\d+):(\d+)", raw)
    if pmp450_match:
        days = pmp450_match.group(1)
        time = f"{pmp450_match.group(2)}:{pmp450_match.group(3)}:{pmp450_match.group(4)}"
        return f"{days} days, {time}"

    # Return substring after ' up ' until the next comma (uptime portion only)
    m = re.search(r"up ([^,]+(?:, \d+ min|, \d+ days|, \d+:\d+)?)(?:,|\s+user)", raw)
    if m:
        return m.group(1).strip()
    return raw


def extract_seconds_from_uptime(raw: str) -> Optional[int]:
    # Fallback approximate parser
    # Patterns: X min, HH:MM, X days, HH:MM, etc.
    try:
        # Check for PMP450 Telnet format first: 14d, 23:40:59
        pmp450_match = re.search(r"(\d+)d,\s*(\d+):(\d+):(\d+)", raw)
        if pmp450_match:
            days = int(pmp450_match.group(1))
            hours = int(pmp450_match.group(2))
            mins = int(pmp450_match.group(3))
            secs = int(pmp450_match.group(4))
            return days * 86400 + hours * 3600 + mins * 60 + secs

        # If we can read /proc/uptime output form, bail out (not here)
        # Very naive parse:
        days = 0
        hours = 0
        mins = 0
        # days
        md = re.search(r"(\d+)\s+day", raw)
        if md:
            days = int(md.group(1))
        # time HH:MM
        mt = re.search(r"(\d+):(\d+)", raw)
        if mt:
            hours = int(mt.group(1))
            mins = int(mt.group(2))
        else:
            # maybe "X min"
            mm = re.search(r"(\d+)\s+min", raw)
            if mm:
                mins = int(mm.group(1))
        return days * 86400 + hours * 3600 + mins * 60
    except Exception:
        return None


def parse_arp(raw: str) -> List[Dict[str, Any]]:
    """
    Typical busybox arp -n output lines, example:
    IP address       HW type     Flags       HW address            Mask     Device
    192.168.0.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        br0
    """
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return []
    # Drop header if recognized
    if "IP address" in lines[0]:
        lines = lines[1:]
    clients = []
    for line in lines:
        # Match lines like: ? (10.40.100.235) at ... or (10.40.100.1) at ...
        m = re.match(r"(?:\?\s*)?\(([^)]+)\) at ([0-9a-f:]+) \[ether\]\s+on (\S+)", line)
        if m:
            ip = m.group(1)
            mac = m.group(2)
            iface = m.group(3)
            clients.append({"ip": ip, "mac": mac, "interface": iface})
        else:
            # fallback: try to parse with old logic
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[0]
                mac = parts[3]
                iface = parts[-1]
                clients.append({"ip": ip, "mac": mac, "interface": iface})
    return clients


def parse_dumpleases(raw: str) -> Dict[str, Dict[str, Any]]:
    """Parse dumpleases -f /var/udhcpd.leases output into dict keyed by MAC.

    Returns mapping mac -> {hostname, ip, expires_seconds}
    """
    leases: Dict[str, Dict[str, Any]] = {}
    lines = [l for l in raw.splitlines() if l.strip() and not l.startswith('#')]
    # Skip header if present
    for line in lines:
        # Example: iPad             d6:73:46:19:4f:58 192.168.11.95   15:27:20
        m = re.match(r"^(?P<hostname>\S+)\s+(?P<mac>[0-9a-f:]+)\s+(?P<ip>\S+)\s+(?P<expires>\d{1,2}:\d{2}:\d{2})$", line)
        if m:
            hostname = m.group('hostname')
            mac = m.group('mac').lower()
            ip = m.group('ip')
            expires = m.group('expires')
            # Convert HH:MM:SS to seconds remaining approximate
            try:
                h, mm, s = [int(x) for x in expires.split(':')]
                expires_seconds = h * 3600 + mm * 60 + s
            except Exception:
                expires_seconds = None
            leases[mac] = {"hostname": hostname, "ip": ip, "expires_seconds": expires_seconds}
    return leases


def parse_brctl_show(raw: str, bridge: str = 'br0') -> List[str]:
    """Return ordered list of interfaces attached to bridge (br0)."""
    lines = raw.splitlines()
    iface_list: List[str] = []
    current_bridge = None
    for i, line in enumerate(lines):
        parts = line.split()
        if not parts:
            continue
        # Bridge header line: br0 8000.id STP enabled interfaces
        if parts[0] == bridge:
            # following lines (indented) list interfaces
            j = i + 1
            while j < len(lines) and lines[j].startswith(' '):
                iface = lines[j].strip()
                if iface:
                    iface_list.append(iface)
                j += 1
            break
    return iface_list


def parse_brctl_showmacs(raw: str) -> Dict[str, int]:
    """Parse brctl showmacs output into mac -> port_no mapping (non-local entries)."""
    mapping: Dict[str, int] = {}
    for line in raw.splitlines():
        # Example line formats:
        #   4     60:dd:8e:70:2a:1a       no                 0.85
        #   1     bc:e6:7c:0f:b8:70       yes                0.00
        m = re.match(r"^\s*(?P<port>\d+)\s+(?P<mac>[0-9a-f:]+)\s+(?P<is_local>yes|no)\s+\S+", line, re.I)
        if m:
            is_local = m.group('is_local').lower()
            if is_local != 'no':
                # skip local entries (the AP's own BSSIDs)
                continue
            port = int(m.group('port'))
            mac = m.group('mac').lower()
            mapping[mac] = port
    return mapping


def map_iface_label(iface: str, interface_map=None) -> str:
    """
    Map network interface name to logical type.

    Args:
        iface: Interface name (e.g., 'ra0', 'eth0')
        interface_map: Optional InterfaceMapping object for model-specific mapping

    Returns:
        str: Logical interface type
    """
    # If interface_map provided, use it
    if interface_map:
        from app.device_models import map_interface_to_type
        return map_interface_to_type(iface, interface_map)

    # Default hardcoded mapping (backward compatibility)
    if iface.startswith('eth'):
        return 'wired'
    if iface == 'ra0' or iface == 'wds0':
        return 'wifi_2.4ghz'
    if iface == 'rai0' or iface == 'wdsi0':
        return 'wifi_5ghz'
    if iface == 'ra1':
        return 'wifi_guest'
    return 'unknown_or_idle'


def assemble_clients(
    leases: Dict[str, Dict[str, Any]],
    br_ifaces: List[str],
    mac_port_map: Dict[str, int],
    arp_clients: List[Dict[str, Any]],
    interface_map=None
) -> List[Dict[str, Any]]:
    """Combine data sources and return enriched client dicts.

    Fields: ip, mac, interface (label), hostname (optional), active (bool), lease_expires_seconds (optional)

    Args:
        leases: DHCP lease information
        br_ifaces: Bridge interface list
        mac_port_map: MAC to port mapping from brctl
        arp_clients: ARP table entries
        interface_map: Optional InterfaceMapping for model-specific interface names
    """
    clients: Dict[str, Dict[str, Any]] = {}
    # Start from leases
    for mac, info in leases.items():
        clients[mac] = {
            'mac': mac,
            'ip': info.get('ip'),
            'hostname': info.get('hostname'),
            'lease_expires_seconds': info.get('expires_seconds'),
            'active': False,
            'interface': 'unknown_or_idle',
        }

    # Add ARP info (may contain IPs for MACs not in leases)
    bridged_ifaces = set(br_ifaces or [])
    for entry in arp_clients:
        mac = entry.get('mac', '').lower()
        if not mac:
            continue
        entry_iface = entry.get('interface')
        # Determine if this ARP entry is on a bridged iface (br0 or one of br_ifaces)
        is_on_bridge = False
        if entry_iface:
            if entry_iface == 'br0' or entry_iface in bridged_ifaces:
                is_on_bridge = True
        # Active only if on the bridge or we have a brctl mapping for the mac
        is_active = is_on_bridge or (mac in mac_port_map)
        if mac not in clients:
            clients[mac] = {
                'mac': mac,
                'ip': entry.get('ip'),
                'hostname': None,
                'lease_expires_seconds': None,
                'active': bool(is_active),
                'interface': entry_iface or 'unknown_or_idle'
            }
        else:
            # update ip and mark active only when appropriate
            clients[mac]['ip'] = clients[mac].get('ip') or entry.get('ip')
            if is_active:
                clients[mac]['active'] = True

    # Map macs from brctl showmacs to interfaces and mark active only if mapped to a bridged iface
    for mac, port in mac_port_map.items():
        # port numbers start at 1; br_ifaces is ordered list
        idx = port - 1
        iface = br_ifaces[idx] if 0 <= idx < len(br_ifaces) else None
        iface_label = map_iface_label(iface, interface_map) if iface else 'unknown_or_idle'
        # If iface looks like a WAN uplink (e.g., eth2.1) skip marking active
        if iface and iface.startswith('eth') and '.1' in iface:
            continue
        if mac not in clients:
            clients[mac] = {
                'mac': mac,
                'ip': None,
                'hostname': None,
                'lease_expires_seconds': None,
                'active': True,
                'interface': iface_label,
            }
        else:
            if iface:
                clients[mac]['interface'] = iface_label
            clients[mac]['active'] = True

    # Finally, produce a list
    result: List[Dict[str, Any]] = []
    for mac, info in clients.items():
        result.append({
            'mac': mac,
            'ip': info.get('ip'),
            'hostname': info.get('hostname'),
            'interface': info.get('interface'),
            'active': bool(info.get('active')),
            'lease_expires_seconds': info.get('lease_expires_seconds'),
        })
    # sort by ip if present, else mac
    result.sort(key=lambda x: (x.get('ip') or '', x.get('mac')))
    return result
