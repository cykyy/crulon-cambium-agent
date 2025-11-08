from fastapi import APIRouter, HTTPException, Depends
import logging

from app.auth import require_token
from app.models import UpdateSSIDPasswordRequest, RebootRequest
from app.services import collect_router_info, ssh_client, run_cmd
from app.utils import validate_ip
from app.config import ROUTER_USER, ROUTER_PASS, DEBUG_MODE

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/debug/env-check")
def debug_env_check(ip: str | None = None, _: None = Depends(require_token)):
    """Debug endpoint to check environment variables and SSH connection.

    Only available when DEBUG_MODE=true is set in environment.

    Query params:
    - ip (optional): If provided, tests SSH connection to this router
    """
    if not DEBUG_MODE:
        raise HTTPException(status_code=404, detail="Debug endpoints are disabled in production")

    import paramiko

    result = {
        "env_vars": {},
        "password_analysis": {},
        "ssh_test": None
    }

    # Check environment variables
    result["env_vars"] = {
        "ROUTER_USER": ROUTER_USER if ROUTER_USER else "[NOT SET]",
        "ROUTER_USER_length": len(ROUTER_USER) if ROUTER_USER else 0,
        "ROUTER_PASS_set": bool(ROUTER_PASS),
        "ROUTER_PASS_length": len(ROUTER_PASS) if ROUTER_PASS else 0,
    }

    # Analyze password safely
    if ROUTER_PASS:
        # Safe preview (first 2 and last 2 characters)
        if len(ROUTER_PASS) >= 4:
            safe_preview = f"{repr(ROUTER_PASS[:2])}...{repr(ROUTER_PASS[-2:])}"
        else:
            safe_preview = f"***{len(ROUTER_PASS)}chars***"

        # Check for special characters
        special_chars = set('$"\'\\`@ ')
        found_special = [c for c in special_chars if c in ROUTER_PASS]

        # Check for whitespace issues
        has_leading_ws = ROUTER_PASS != ROUTER_PASS.lstrip()
        has_trailing_ws = ROUTER_PASS != ROUTER_PASS.rstrip()

        result["password_analysis"] = {
            "preview": safe_preview,
            "has_special_chars": len(found_special) > 0,
            "special_chars_found": found_special,
            "has_leading_whitespace": has_leading_ws,
            "has_trailing_whitespace": has_trailing_ws,
            "utf8_hex_preview": ROUTER_PASS.encode('utf-8')[:20].hex(),
        }
    else:
        result["password_analysis"] = {"error": "ROUTER_PASS not set"}

    # Test SSH connection if IP provided
    if ip:
        try:
            validate_ip(ip)
            result["ssh_test"] = {
                "target": ip,
                "status": "attempting",
                "details": {}
            }

            # Try to connect
            with ssh_client(ip, ROUTER_USER, ROUTER_PASS) as client:
                transport = client.get_transport()

                result["ssh_test"]["status"] = "SUCCESS"
                result["ssh_test"]["details"] = {
                    "connected": True,
                    "authenticated": transport.is_authenticated() if transport else False,
                }

        except paramiko.AuthenticationException as e:
            result["ssh_test"]["status"] = "AUTH_FAILED"
            result["ssh_test"]["error_type"] = "AuthenticationException"
            result["ssh_test"]["error_message"] = str(e)
            result["ssh_test"]["diagnosis"] = "Password is likely incorrect or has encoding issues"

        except paramiko.SSHException as e:
            result["ssh_test"]["status"] = "SSH_ERROR"
            result["ssh_test"]["error_type"] = "SSHException"
            result["ssh_test"]["error_message"] = str(e)

        except Exception as e:
            result["ssh_test"]["status"] = "FAILED"
            result["ssh_test"]["error_type"] = type(e).__name__
            result["ssh_test"]["error_message"] = str(e)

    return result


@router.get("/router/summary")
def router_summary(ip: str, model: str | None = None, _: None = Depends(require_token)):
    """Return a small summary: online status, uptime, device type, and total connected devices/link status.

    Query Parameters:
        ip: Device IP address
        model: Optional model hint (e.g., 'pmp_450', 'force_300', 'R195W') to skip auto-detection
    """
    validate_ip(ip)
    try:
        data = collect_router_info(ip, model)
    except HTTPException:
        raise
    except Exception as e:
        # If we couldn't reach the router, report offline
        logger.error(f"Exception in router_summary for {ip}: {e}", exc_info=True)
        return {"router": ip, "online": False, "error": str(e)}

    clients = data.get("clients", []) or []
    total_active = sum(1 for c in clients if c.get("active"))
    uptime_seconds = data.get("uptime", {}).get("uptime_seconds")

    result = {
        "router": ip,
        "online": True,
        "device_type": data.get("device_type"),
        "uptime_seconds": uptime_seconds
    }

    # Add device-specific fields based on capabilities
    capabilities = data.get("capabilities", {})

    # Build contextual notes
    notes = []

    # Only include total_devices for WiFi routers
    if capabilities.get("has_wifi"):
        result["total_devices"] = total_active
        if capabilities.get("dual_band"):
            notes.append("This is a dual-band WiFi router (2.4GHz + 5GHz)")
        else:
            notes.append("This is a single-band WiFi router (2.4GHz only)")
    else:
        # Bridge device notes
        notes.append("This is a wireless bridge/backhaul device, not a WiFi router")
        notes.append("No WiFi clients - provides point-to-point link metrics")

    # Add link metrics for bridge devices
    if capabilities.get("has_link_metrics"):
        result["link_status"] = data.get("link_status")
        result["signal_strength"] = data.get("signal_strength")
        result["tx_rate_mbps"] = data.get("tx_rate_mbps")
        result["rx_rate_mbps"] = data.get("rx_rate_mbps")

    result["notes"] = notes
    return result


@router.get("/router/wifi")
def router_wifi(ip: str, model: str | None = None, _: None = Depends(require_token)):
    """Return SSID and password info for the router (WiFi-capable devices only).

    Query Parameters:
        ip: Device IP address
        model: Optional model hint (e.g., 'pmp_450', 'force_300', 'R195W') to skip auto-detection
    """
    validate_ip(ip)
    try:
        data = collect_router_info(ip, model)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Check if device supports WiFi
    capabilities = data.get("capabilities", {})
    if not capabilities.get("has_wifi"):
        device_type = data.get("device_type", "unknown")
        raise HTTPException(
            status_code=400,
            detail=f"Device type '{device_type}' does not support WiFi credentials. "
                   "This is a wireless bridge/backhaul device, not a WiFi router."
        )

    return {
        "router": ip,
        "device_type": data.get("device_type"),
        "ssid_2g": data.get("ssid_2g"),
        "ssid_5g": data.get("ssid_5g"),
        "password_2g": data.get("password_2g"),
        "password_5g": data.get("password_5g"),
    }


@router.get("/router/clients")
def router_clients(ip: str, model: str | None = None, _: None = Depends(require_token)):
    """Return connected WiFi clients (WiFi routers) or link info (bridge devices).

    Query Parameters:
        ip: Device IP address
        model: Optional model hint (e.g., 'pmp_450', 'force_300', 'R195W') to skip auto-detection
    """
    validate_ip(ip)
    try:
        data = collect_router_info(ip, model)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    result = {
        "router": ip,
        "device_type": data.get("device_type"),
        "clients": data.get("clients", [])
    }

    # Add link info for bridge devices
    capabilities = data.get("capabilities", {})
    if capabilities.get("has_link_metrics"):
        result["link_status"] = data.get("link_status")
        result["signal_strength"] = data.get("signal_strength")
        result["link_quality"] = data.get("link_quality")
        result["tx_rate_mbps"] = data.get("tx_rate_mbps")
        result["rx_rate_mbps"] = data.get("rx_rate_mbps")

    return result


@router.get("/router/raw")
def router_raw(ip: str, model: str | None = None, _: None = Depends(require_token)):
    """Return the full collected data (raw outputs included).

    Query Parameters:
        ip: Device IP address
        model: Optional model hint (e.g., 'pmp_450', 'force_300', 'R195W') to skip auto-detection
    """
    validate_ip(ip)
    try:
        data = collect_router_info(ip, model)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return data


@router.post("/router/update")
def update_router_ssid_password(
        req: UpdateSSIDPasswordRequest,
        _: None = Depends(require_token)
):
    """Update router SSID and/or password and optionally reboot (WiFi routers only)."""
    from app.services import create_device_adapter
    from app.detection import detect_device_type
    from app.connection import connect_to_device, connect_direct
    from app.device_models import validate_and_parse_model, DEVICE_CONNECTION_TYPE

    validate_ip(req.ip)
    updates = []

    # Try model hint first if provided
    if req.model:
        try:
            device_type = validate_and_parse_model(req.model)
            connection_type = DEVICE_CONNECTION_TYPE[device_type]

            with connect_direct(req.ip, connection_type, ROUTER_USER, ROUTER_PASS) as client:
                adapter = create_device_adapter(client, req.ip, device_type, connection_type)

                # Check if device supports WiFi credential updates
                if not adapter.capabilities.has_wifi and (req.ssid or req.password):
                    return {
                        "success": False,
                        "updated": [],
                        "errors": f"Device type '{device_type.value}' does not support WiFi credential updates. "
                                 "This is a wireless bridge/backhaul device."
                    }

                # Update WiFi credentials
                if req.ssid or req.password:
                    success = adapter.update_wifi_credentials(ssid=req.ssid, password=req.password)
                    if success:
                        if req.ssid:
                            updates.append("ssid")
                        if req.password:
                            updates.append("password")
                    else:
                        return {"success": False, "updated": [], "errors": "Failed to update WiFi credentials"}

                # Reboot if requested
                if req.reboot:
                    reboot_success = adapter.reboot()
                    if reboot_success:
                        updates.append("rebooted")
                    else:
                        return {"success": False, "updated": updates, "errors": "Failed to reboot device"}

                if not updates:
                    return {"success": False, "updated": [], "errors": "No update fields provided."}
                return {"success": True, "updated": updates, "errors": None}

        except Exception as e:
            logger.debug(f"Model hint '{req.model}' failed: {e}. Falling back to auto-detection")
            # Fall through to auto-detection

    # Auto-detection flow (no model hint or model hint failed)
    try:
        with connect_to_device(req.ip, ROUTER_USER, ROUTER_PASS) as (client, connection_type):
            # Detect device type
            device_type = detect_device_type(client, connection_type)
            adapter = create_device_adapter(client, req.ip, device_type, connection_type)

            # Check if device supports WiFi credential updates
            if not adapter.capabilities.has_wifi and (req.ssid or req.password):
                return {
                    "success": False,
                    "updated": [],
                    "errors": f"Device type '{device_type.value}' does not support WiFi credential updates. "
                             "This is a wireless bridge/backhaul device."
                }

            # Update WiFi credentials
            if req.ssid or req.password:
                success = adapter.update_wifi_credentials(ssid=req.ssid, password=req.password)
                if success:
                    if req.ssid:
                        updates.append("ssid")
                    if req.password:
                        updates.append("password")
                else:
                    return {"success": False, "updated": [], "errors": "Failed to update WiFi credentials"}

            # Reboot if requested
            if req.reboot:
                reboot_success = adapter.reboot()
                if reboot_success:
                    updates.append("rebooted")
                else:
                    return {"success": False, "updated": updates, "errors": "Failed to reboot device"}

        if not updates:
            return {"success": False, "updated": [], "errors": "No update fields provided."}
        return {"success": True, "updated": updates, "errors": None}
    except Exception as e:
        return {"success": False, "updated": [], "errors": str(e)}


@router.post("/router/reboot")
def router_reboot(req: RebootRequest, _: None = Depends(require_token)):
    """Trigger a reboot on the target device. Returns JSON with success and errors.

    Body
    ----
    ip: str  -- IPv4/IPv6 address of the device to reboot
    model: Optional[str] -- Model hint (e.g., 'pmp_450', 'force_300', 'R195W') to skip auto-detection
    """
    from app.services import create_device_adapter
    from app.detection import detect_device_type
    from app.connection import connect_to_device, connect_direct
    from app.device_models import validate_and_parse_model, DEVICE_CONNECTION_TYPE

    validate_ip(req.ip)

    # Try model hint first if provided
    if req.model:
        try:
            device_type = validate_and_parse_model(req.model)
            connection_type = DEVICE_CONNECTION_TYPE[device_type]

            with connect_direct(req.ip, connection_type, ROUTER_USER, ROUTER_PASS) as client:
                adapter = create_device_adapter(client, req.ip, device_type, connection_type)

                # Reboot using adapter
                success = adapter.reboot()
                if success:
                    return {"success": True, "errors": None}
                else:
                    return {"success": False, "errors": "Reboot command failed"}

        except Exception as e:
            logger.debug(f"Model hint '{req.model}' failed: {e}. Falling back to auto-detection")
            # Fall through to auto-detection

    # Auto-detection flow (no model hint or model hint failed)
    try:
        with connect_to_device(req.ip, ROUTER_USER, ROUTER_PASS) as (client, connection_type):
            # Detect device type and create adapter
            device_type = detect_device_type(client, connection_type)
            adapter = create_device_adapter(client, req.ip, device_type, connection_type)

            # Reboot using adapter
            success = adapter.reboot()
            if success:
                return {"success": True, "errors": None}
            else:
                return {"success": False, "errors": "Reboot command failed"}
    except Exception as e:
        # Return success false and include error message for client-side handling
        return {"success": False, "errors": str(e)}
