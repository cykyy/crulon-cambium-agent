# Crulon Cambium Agent

On-premise agent for managing Cambium network equipment via SSH. Provides REST API endpoints to query device status, WiFi credentials (routers), link metrics (bridges), connected devices, and update settings.

## Supported Devices

The system automatically detects the device model and provides appropriate functionality:

### WiFi Routers
- **cnPilot R195W** (dual-band 2.4GHz + 5GHz)
- **cnPilot R200, R201** (dual-band)
- **cnPilot R190W** (single-band 2.4GHz)

Supports: WiFi SSIDs/passwords, connected clients, network configuration

### Wireless Bridges/Backhaul
- **Force 200** (point-to-point bridge)
- **Force 300** (point-to-point bridge)
- **PMP450** (point-to-multipoint)

Supports: Link status, signal strength, TX/RX rates, network config, device info, reboot (no WiFi credentials)

## Quick Start

### Using Docker Compose (Recommended)

1. Create a `.env` file:
```bash
ROUTER_USER=admin
ROUTER_PASS=your_router_password
API_TOKEN=your_secret_token
PORT=8000
```

2. Start the service:
```bash
docker-compose up -d
```

3. Verify it's running:
```bash
curl http://localhost:8000/health
```

### Using Docker

```bash
docker build -t cambium-agent .
docker run -d -p 8000:8000 \
  -e ROUTER_USER=admin \
  -e ROUTER_PASS=your_router_password \
  -e API_TOKEN=your_secret_token \
  cambium-agent
```

## Configuration

Required environment variables:

| Variable | Description | Example    |
|----------|-------------|------------|
| `ROUTER_USER` | SSH username for router | `admin`    |
| `ROUTER_PASS` | SSH password for router | `Password` |
| `API_TOKEN` | API authentication token | `1234`     |
| `PORT` | Server port (optional) | `8000`     |

### Debug Endpoint

If you're having authentication issues, use the debug endpoint to diagnose:

```bash
# Check environment variables and password analysis
curl -H "X-API-Token: your_token" \
  "http://localhost:8000/debug/env-check"

# Test SSH connection to a router
curl -H "X-API-Token: your_token" \
  "http://localhost:8000/debug/env-check?ip=192.168.1.1"
```

This will show:
- If ROUTER_PASS is loaded correctly
- Password length and safe preview
- Special characters detected
- Whitespace issues
- SSH connection test results (if IP provided)

## Performance Optimization - Model Parameter

All endpoints accept an optional `model` parameter to skip auto-detection and improve response time.

**Supported model formats** (case-insensitive, pattern-matched):
- Exact: `pmp_450`, `force_300`, `force_200`, `cnpilot_dual_band`, `cnpilot_single_band`
- Friendly: `R195W`, `R200`, `R201`, `R190W`, `PMP450`, `Force 300`, `Force 200`
- Variants: `pmp450d sm/5ghz`, `pmp450 sm/3.65`, `pmp450B high gain`, `REG-PL-R195W`

**How it works:**
- If model specified: skips auto-detection, uses model's connection type (SSH/Telnet) directly
- If model invalid or connection fails: automatically falls back to auto-detection
- If not specified: uses standard auto-detection flow

**Usage:**
```bash
# GET endpoints (query parameter)
curl -H "X-API-Token: 1234" "http://localhost:8000/router/summary?ip=192.168.1.1&model=pmp_450"

# POST endpoints (request body)
curl -X POST http://localhost:8000/router/reboot \
  -H "X-API-Token: 1234" -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1", "model": "force 300"}'
```

## API Endpoints

All endpoints (except `/health`) require authentication via:
- Header: `X-API-Token: your_token`
- OR Query: `?api_token=your_token`

---

### Health Check

Check if the service is running.

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{"status": "ok"}
```

---

### Router Summary

Get device online status, type, uptime, and total connected devices (or link status for bridges).

```bash
# Auto-detection
curl -H "X-API-Token: 1234" \
  "http://localhost:8000/router/summary?ip=192.168.1.1"

# With model hint for faster response
curl -H "X-API-Token: 1234" \
  "http://localhost:8000/router/summary?ip=192.168.1.1&model=pmp_450"
```

**Response (WiFi Router - Online):**
```json
{
  "router": "192.168.1.1",
  "online": true,
  "device_type": "cnpilot_dual_band",
  "uptime_seconds": 432000,
  "total_devices": 5
}
```

**Response (Wireless Bridge - Online):**
```json
{
  "router": "10.14.244.106",
  "online": true,
  "device_type": "force_200",
  "uptime_seconds": 86400,
  "total_devices": 0,
  "link_status": "up",
  "signal_strength": -65,
  "tx_rate_mbps": 150,
  "rx_rate_mbps": 150
}
```

**Response (Offline):**
```json
{
  "router": "192.168.1.1",
  "online": false,
  "error": "Connection timeout..."
}
```

---

### WiFi Credentials

Get WiFi network names and passwords for 2.4GHz and 5GHz bands (WiFi routers only).

```bash
# Auto-detection
curl -H "X-API-Token: 1234" \
  "http://localhost:8000/router/wifi?ip=192.168.1.1"

# With model hint
curl -H "X-API-Token: 1234" \
  "http://localhost:8000/router/wifi?ip=192.168.1.1&model=R195W"
```

**Response (WiFi Router):**
```json
{
  "router": "192.168.1.1",
  "device_type": "cnpilot_dual_band",
  "ssid_2g": "MyNetwork_2.4 Ghzs",
  "ssid_5g": "MyNetwork_5 Ghzs",
  "password_2g": "password123",
  "password_5g": "password123"
}
```

**Response (Single-Band Router):**
```json
{
  "router": "192.168.1.2",
  "device_type": "cnpilot_single_band",
  "ssid_2g": "MyNetwork_2.4 Ghzs",
  "ssid_5g": null,
  "password_2g": "password123",
  "password_5g": null
}
```

**Error (Wireless Bridge):**
```json
{
  "detail": "Device type 'force_200' does not support WiFi credentials. This is a wireless bridge/backhaul device, not a WiFi router."
}
```
HTTP Status: 400

---

### Connected Clients

Get list of all devices connected to the router (WiFi routers) or link status (bridges).

```bash
curl -H "X-API-Token: 1234" \
  "http://localhost:8000/router/clients?ip=192.168.1.1"
```

**Response (WiFi Router):**
```json
{
  "router": "192.168.1.1",
  "device_type": "cnpilot_dual_band",
  "clients": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "ip": "192.168.1.100",
      "hostname": "iPhone",
      "interface": "wifi_5ghz",
      "active": true,
      "lease_expires_seconds": 3600
    }
  ]
}
```

**Response (Wireless Bridge):**
```json
{
  "router": "10.14.244.106",
  "device_type": "force_200",
  "clients": [],
  "link_status": "up",
  "signal_strength": -65,
  "link_quality": 85,
  "tx_rate_mbps": 150,
  "rx_rate_mbps": 150
}
```

**Interface Types (WiFi Routers):**
- `wifi_2.4ghz` - 2.4GHz WiFi
- `wifi_5ghz` - 5GHz WiFi
- `wifi_guest` - Guest network
- `wired` - Ethernet connection
- `unknown_or_idle` - Unknown or inactive

---

### Raw Router Data

Get complete router information including all raw command outputs.

```bash
curl -H "X-API-Token: 1234" \
  "http://localhost:8000/router/raw?ip=192.168.1.1"
```

**Response:**
```json
{
  "timestamp": 1699459200,
  "router": "192.168.1.1",
  "ssid_2g": "MyNetwork_2.4 Ghzs",
  "ssid_5g": "MyNetwork_5 Ghzs",
  "password_2g": "password123",
  "password_5g": "password123",
  "uptime": {
    "raw": " 14:12:33 up 5 days, 3:17, 1 user, load average: 0.00",
    "uptime_human": "5 days, 3:17",
    "uptime_seconds": 457020
  },
  "clients": [...],
  "_raw": {
    "arp": "...",
    "proc_arp": "...",
    "leases": "...",
    "brctl": "...",
    "brctl_showmacs": "...",
    "iwconfig": "..."
  }
}
```

---

### Update Router Settings

Change WiFi network name and/or password (WiFi routers only). Optionally reboot after changes.

```bash
curl -X POST http://localhost:8000/router/update \
  -H "X-API-Token: 1234" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1",
    "ssid": "NewNetwork",
    "password": "newpass123",
    "reboot": false
  }'
```

**Request Body:**
- `ip` (required) - Router IP address
- `ssid` (optional) - New network name (will append "_2.4 Ghzs" and "_5 Ghzs")
- `password` (optional) - New WiFi password
- `reboot` (optional) - Reboot router after changes (default: false)
- `model` (optional) - Model hint to skip auto-detection (e.g., "R195W", "pmp_450")

**Response (Success):**
```json
{
  "success": true,
  "updated": ["ssid", "password"],
  "errors": null
}
```

**Response (Wireless Bridge Error):**
```json
{
  "success": false,
  "updated": [],
  "errors": "Device type 'force_200' does not support WiFi credential updates. This is a wireless bridge/backhaul device."
}
```

**Response (Other Error):**
```json
{
  "success": false,
  "updated": [],
  "errors": "Connection failed..."
}
```

---

### Reboot Device

Restart the device (works for all device types).

```bash
curl -X POST http://localhost:8000/router/reboot \
  -H "X-API-Token: 1234" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.1",
    "model": "force 300"
  }'
```

**Request Body:**
- `ip` (required) - Device IP address
- `model` (optional) - Model hint to skip auto-detection (e.g., "pmp_450", "force 300")

**Response:**
```json
{
  "success": true,
  "errors": null
}
```

---

## Multi-Model Architecture

The agent automatically detects the device model on first connection and adapts its behavior accordingly:

1. **Auto-Detection**: Uses multiple detection strategies in priority order:
    - Cambium CLI detection (`show dashboard` for Force/PMP devices)
    - Shell-based detection (`show version`, `nvram_get` for cnPilot routers)
    - Filesystem analysis (`/proc/cpuinfo`, `/etc/config`)
2. **Device Adapters**: Each device type has a specialized adapter providing appropriate functionality
    - cnPilot adapters use NVRAM commands for WiFi configuration
    - Force/PMP adapters use Cambium CLI commands (`show wireless`, `show rssi`, `show ip`)
3. **Enhanced Metrics**: Force devices collect comprehensive link data using multiple CLI commands:
    - `show dashboard` - Overall device status and uptime
    - `show rssi` - Accurate signal strength measurements
    - `show wireless` - TX/RX rates and detailed wireless statistics
    - `show ip` - Network configuration details
4. **Graceful Errors**: WiFi-specific endpoints return clear error messages for bridge devices
5. **Unified API**: Same endpoints work for all device types with appropriate responses

### Device Type Values

API responses include a `device_type` field with these possible values:

- `cnpilot_dual_band` - cnPilot R195W, R200, R201 (2.4GHz + 5GHz)
- `cnpilot_single_band` - cnPilot R190W (2.4GHz only)
- `force_200` - Force 200 wireless bridge
- `force_300` - Force 300 wireless bridge
- `pmp_450` - PMP450 point-to-multipoint equipment
- `unknown` - Device type could not be determined

### Testing with Multiple Models

When you have mixed deployments:

```bash
# WiFi Router - all endpoints work
curl -H "X-API-Token: 1234" "http://localhost:8000/router/wifi?ip=192.168.1.1"

# Wireless Bridge - WiFi endpoints return errors, summary/clients return link info
curl -H "X-API-Token: 1234" "http://localhost:8000/router/summary?ip=10.14.244.106"
curl -H "X-API-Token: 1234" "http://localhost:8000/router/wifi?ip=10.14.244.106"  # Returns 400 error

# Reboot works for all device types
curl -X POST http://localhost:8000/router/reboot -H "X-API-Token: 1234" -H "Content-Type: application/json" -d '{"ip": "192.168.1.1"}'
```

---

## Development

Run without Docker:

```bash
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
