from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import TYPE_CHECKING, Any

from ..constants import PROXY_HOST, XRAY_TUN_DEFAULT_ADDRESS, XRAY_TUN_DEFAULT_ADDRESS_V6, XRAY_TUN_DEFAULT_INTERFACE_NAME, XRAY_TUN_DEFAULT_MTU
from ..engines.xray import get_windows_default_route_context
from .connection_service import find_free_api_port
from .runtime_introspection import extract_xray_runtime_ports
from .runtime_security import strip_xray_proxy_inbounds
from .session_state import XrayRuntimeConfig

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


APP_METRICS_API_TAG = "__app_metrics_api"
APP_METRICS_API_INBOUND_TAG = "__app_metrics_api_in"
APP_TUN_INBOUND_TAG = "__app_tun_in"


def inspect_active_xray_config(controller: AppController) -> tuple:
    path, text = controller.load_active_xray_config_text()
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    has_proxy_outbound = False
    socks_port = 0
    http_port = 0
    api_port = 0
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if payload is not None:
        ensure_xray_metrics_contract(controller, payload, allocate_port=False)
        has_proxy_outbound = controller._config_has_proxy_outbound(payload)
        socks_port, http_port, api_port = extract_xray_runtime_ports(payload)
    return path, text_hash, has_proxy_outbound, socks_port, http_port, api_port


def ensure_xray_metrics_contract(
    controller: AppController,
    payload: dict[str, Any],
    *,
    allocate_port: bool,
) -> tuple[int, tuple[str, ...]]:
    stats = payload.get("stats")
    if not isinstance(stats, dict):
        payload["stats"] = {}

    policy = controller._ensure_dict(payload, "policy")
    system_policy = controller._ensure_dict(policy, "system")
    system_policy["statsInboundUplink"] = True
    system_policy["statsInboundDownlink"] = True
    system_policy["statsOutboundUplink"] = True
    system_policy["statsOutboundDownlink"] = True

    outbounds = controller._ensure_list(payload, "outbounds")
    api = controller._ensure_dict(payload, "api")
    existing_api_tag = str(api.get("tag") or "").strip()
    api_tag = APP_METRICS_API_TAG
    if existing_api_tag:
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            if str(outbound.get("tag") or "").strip() != existing_api_tag:
                continue
            protocol = str(outbound.get("protocol") or "").strip().lower()
            if protocol in {"freedom", "loopback"}:
                api_tag = existing_api_tag
            break
    api["tag"] = api_tag
    services = api.get("services")
    normalized_services = [str(item) for item in services] if isinstance(services, list) else []
    if "StatsService" not in normalized_services:
        normalized_services.append("StatsService")
    api["services"] = normalized_services

    inbounds = controller._ensure_list(payload, "inbounds")
    existing_ports = controller._collect_xray_inbound_ports(payload)

    preferred_api_port = 0
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("tag") or "") != APP_METRICS_API_INBOUND_TAG:
            continue
        try:
            preferred_api_port = int(inbound.get("port") or 0)
        except (TypeError, ValueError):
            preferred_api_port = 0
        if preferred_api_port > 0:
            existing_ports.discard(preferred_api_port)
        break

    if preferred_api_port > 0:
        api_port = preferred_api_port
    elif allocate_port:
        try:
            api_port = find_free_api_port(excluded=existing_ports)
        except RuntimeError as exc:
            raise ValueError("Не удалось выделить локальный порт для Xray metrics API.") from exc
    else:
        api_port = 0

    metrics_inbound = {
        "tag": APP_METRICS_API_INBOUND_TAG,
        "listen": PROXY_HOST,
        "port": api_port,
        "protocol": "dokodemo-door",
        "settings": {"address": PROXY_HOST},
    }
    controller._replace_or_append_tagged(inbounds, APP_METRICS_API_INBOUND_TAG, metrics_inbound)

    has_api_outbound = any(
        isinstance(outbound, dict) and str(outbound.get("tag") or "") == api_tag
        for outbound in outbounds
    )
    if not has_api_outbound:
        outbounds.append({"tag": api_tag, "protocol": "freedom", "settings": {}})

    user_inbound_tags: list[str] = []
    for index, inbound in enumerate(inbounds):
        if not isinstance(inbound, dict):
            continue
        tag = str(inbound.get("tag") or "").strip()
        if tag == APP_METRICS_API_INBOUND_TAG:
            continue
        if not tag:
            tag = f"__app_user_inbound_{index}"
            inbound["tag"] = tag
        if tag not in user_inbound_tags:
            user_inbound_tags.append(tag)

    routing = controller._ensure_dict(payload, "routing")
    rules = controller._ensure_list(routing, "rules")
    metrics_rule = {
        "type": "field",
        "inboundTag": [APP_METRICS_API_INBOUND_TAG],
        "outboundTag": api_tag,
    }
    replaced = False
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        inbound_tags = rule.get("inboundTag")
        if isinstance(inbound_tags, list) and APP_METRICS_API_INBOUND_TAG in [str(item) for item in inbound_tags]:
            rules[index] = metrics_rule
            replaced = True
            break
    if not replaced:
        rules.insert(0, metrics_rule)

    return api_port, tuple(user_inbound_tags)


def _is_tun_direct_catchall(rule: dict[str, Any]) -> bool:
    """Return True for rules like {"port": "0-65535", "outboundTag": "direct"}.

    In proxy mode these work fine; in TUN mode the freedom outbound sends packets
    back through the TUN interface (routing loop → ERR_CONNECTION_TIMED_OUT).
    A rule is a "catch-all" when its only selector is a wide port range and it has
    no domain/ip/network/protocol/process constraints that limit the match.
    """
    if str(rule.get("outboundTag") or "") != "direct":
        return False
    # Must have a wide port range and nothing else domain/ip-specific
    port_str = str(rule.get("port") or "").strip()
    if not port_str:
        return False
    for key in ("domain", "ip", "process", "protocol"):
        if rule.get(key):
            return False
    # Check if the range covers the full address space (start ≤ 1024, end ≥ 60000)
    if "-" in port_str:
        parts = port_str.split("-", 1)
        try:
            start, end = int(parts[0].strip()), int(parts[1].strip())
            return start <= 1024 and end >= 60000
        except ValueError:
            pass
    return False


def _redirect_tun_direct_catchalls(payload: dict[str, Any]) -> int:
    """In TUN mode, patch catch-all 'direct' port rules to 'proxy' in the runtime config.

    The original config file is never touched — the patch is applied only to the
    in-memory payload that xray will consume.  This is necessary because a v2rayN-
    style config often ends with {"port": "0-65535", "outboundTag": "direct"} which
    works perfectly as a proxy fallback but creates a routing loop in TUN mode:
    freedom's outbound packets re-enter the TUN and timeout.
    """
    routing = payload.get("routing")
    if not isinstance(routing, dict):
        return 0
    rules = routing.get("rules")
    if not isinstance(rules, list):
        return 0
    patched = 0
    for rule in rules:
        if isinstance(rule, dict) and _is_tun_direct_catchall(rule):
            rule["outboundTag"] = "proxy"
            patched += 1
    return patched


def ensure_xray_tun_contract(controller: AppController, payload: dict[str, Any]) -> str:
    """Prepare the xray config for native TUN mode (v2rayN-compatible field names).

    Changes made to the in-memory payload (original file untouched):
    1. Add / fill-in the TUN inbound: gateway, MTU, autoSystemRoutingTable, autoOutboundsInterface.
    2. Add blocking rules for mDNS/NetBIOS ports and multicast IPs.
    3. Patch catch-all 'direct' port rules → 'proxy' to prevent routing loops.
    4. Ensure a DNS section exists so xray can resolve domains inside the tunnel.
    """
    inbounds = controller._ensure_list(payload, "inbounds")

    # --- locate or build TUN inbound ---
    tun_name = XRAY_TUN_DEFAULT_INTERFACE_NAME
    existing_tun: dict[str, Any] | None = None
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("protocol") or "").strip().lower() == "tun":
            existing_tun = inbound
            break

    _DEFAULT_GATEWAY = [XRAY_TUN_DEFAULT_ADDRESS, XRAY_TUN_DEFAULT_ADDRESS_V6]

    if existing_tun is not None:
        settings = controller._ensure_dict(existing_tun, "settings")
        tun_name = str(settings.get("name") or "").strip() or XRAY_TUN_DEFAULT_INTERFACE_NAME
        if not settings.get("name"):
            settings["name"] = tun_name
        # "gateway" is the correct xray field name (not "address")
        if not settings.get("gateway"):
            settings["gateway"] = _DEFAULT_GATEWAY
        settings.pop("address", None)
        settings["MTU"] = XRAY_TUN_DEFAULT_MTU
        settings.pop("mtu", None)
        # autoSystemRoutingTable tells xray to install system routes (WFP on Windows)
        settings.setdefault("autoSystemRoutingTable", ["0.0.0.0/0", "::/0"])
        settings.pop("autoRoute", None)
        # autoOutboundsInterface lets xray bind its own sockets to the physical NIC,
        # preventing the routing loop without needing manual sockopt patches
        settings.setdefault("autoOutboundsInterface", "auto")
        settings.pop("endpointIndependentNat", None)
        sniffing = controller._ensure_dict(existing_tun, "sniffing")
        sniffing.setdefault("enabled", True)
        sniffing.setdefault("destOverride", ["http", "tls", "quic"])
        # routeOnly=true → use the sniffed domain only for the routing decision,
        # but still dial the ORIGINAL destination IP. This makes TUN routing behave
        # exactly like v2rayN's mixed-in proxy inbound: process/domain rules pick the
        # outbound, unmatched (catch-all 'direct') traffic exits the physical NIC by
        # IP with no DNS re-resolve loop, and only matched apps/domains take the proxy.
        sniffing.setdefault("routeOnly", True)
    else:
        inbounds.append(
            {
                "tag": APP_TUN_INBOUND_TAG,
                "protocol": "tun",
                "settings": {
                    "name": tun_name,
                    "MTU": XRAY_TUN_DEFAULT_MTU,
                    "gateway": _DEFAULT_GATEWAY,
                    "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
                    "autoOutboundsInterface": "auto",
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            }
        )

    # --- ensure DNS section so xray resolves domains inside the tunnel ---
    if not payload.get("dns"):
        payload["dns"] = {
            "servers": [
                {"address": "1.1.1.1", "domains": []},
                {"address": "8.8.8.8", "domains": []},
                "localhost",
            ],
            "queryStrategy": "UseIPv4",
        }

    # --- ensure a "block" outbound exists (required for blocking rules below) ---
    outbounds = controller._ensure_list(payload, "outbounds")
    has_block_outbound = any(
        isinstance(ob, dict) and str(ob.get("tag") or "") == "block"
        for ob in outbounds
    )
    if not has_block_outbound:
        outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {}})

    # --- Windows TUN blocking rules: mDNS/NetBIOS ports and multicast IPs ---
    # These prevent WFP conflicts and mDNS/broadcast storms through the tunnel.
    routing = controller._ensure_dict(payload, "routing")
    rules = controller._ensure_list(routing, "rules")
    _TUN_BLOCK_RULES = [
        {"type": "field", "network": "udp", "port": "135,137-139,5353", "outboundTag": "block"},
        {"type": "field", "ip": ["224.0.0.0/3", "ff00::/8"], "outboundTag": "block"},
    ]
    existing_rule_reprs = {str(r) for r in rules}
    for rule in _TUN_BLOCK_RULES:
        if str(rule) not in existing_rule_reprs:
            rules.insert(0, rule)

    # --- patch catch-all direct rules that cause routing loops ---
    # Only needed when xray cannot send the direct/freedom outbound out the
    # physical NIC by itself. With autoOutboundsInterface (always set above) xray
    # binds the direct outbound to the real adapter, so the catch-all 'direct'
    # rule no longer loops and MUST be honored — otherwise every unmatched
    # connection would be forced through the proxy and the whole system would be
    # tunneled instead of just the explicitly routed apps/domains.
    if not _tun_inbound_has_auto_outbounds_interface(payload):
        n = _redirect_tun_direct_catchalls(payload)
        if n:
            controller._log(
                f"[xray-tun] auto-patched {n} catch-all 'port→direct' rule(s) to 'proxy' "
                "(prevents routing loop; original config file unchanged)"
            )

    return tun_name


def xray_outbound_is_loop_protected(outbound: dict[str, Any]) -> bool:
    send_through = str(outbound.get("sendThrough") or "").strip()
    if send_through and send_through not in {"0.0.0.0", "::"}:
        return True
    stream_settings = outbound.get("streamSettings")
    if not isinstance(stream_settings, dict):
        return False
    sockopt = stream_settings.get("sockopt")
    if not isinstance(sockopt, dict):
        return False
    return bool(str(sockopt.get("interface") or "").strip())


def apply_xray_tun_loop_prevention(
    controller: AppController,
    payload: dict[str, Any],
    interface_alias: str,
    source_ip: str = "",
) -> int:
    patched = 0
    outbounds = controller._ensure_list(payload, "outbounds")
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        tag = str(outbound.get("tag") or "").strip()
        protocol = str(outbound.get("protocol") or "").strip().lower()
        if tag in {APP_METRICS_API_TAG, "api"} or protocol in {"blackhole", "loopback", "dns"}:
            continue
        if xray_outbound_is_loop_protected(outbound):
            continue
        # Use BOTH mechanisms for maximum reliability on Windows:
        # • sockopt.interface → IP_UNICAST_IF: forces the kernel to use a specific
        #   network interface regardless of the routing table. This is the primary
        #   loop-breaker (same as WireGuard's approach on Windows).
        # • sendThrough → bind() by source IP: secondary guard for protocols or
        #   xray builds where IP_UNICAST_IF support is incomplete.
        stream_settings = controller._ensure_dict(outbound, "streamSettings")
        sockopt = controller._ensure_dict(stream_settings, "sockopt")
        sockopt["interface"] = interface_alias
        if source_ip and source_ip not in {"0.0.0.0", "::"}:
            outbound["sendThrough"] = source_ip
        patched += 1
    return patched


def _tun_inbound_has_auto_outbounds_interface(payload: dict[str, Any]) -> bool:
    for inbound in (payload.get("inbounds") or []):
        if not isinstance(inbound, dict):
            continue
        if str(inbound.get("protocol") or "").strip().lower() != "tun":
            continue
        val = str((inbound.get("settings") or {}).get("autoOutboundsInterface") or "").strip()
        return bool(val)
    return False


def build_runtime_xray_config(controller: AppController, node: Node | None = None, *, tun_mode: bool = False) -> XrayRuntimeConfig:
    source_path, text = controller.load_active_xray_config_text()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source_path.name}: {controller._format_json_error_message(text, exc)}") from exc

    if not isinstance(payload, dict):
        raise ValueError("Корень xray config должен быть JSON-объектом.")

    tun_interface_name = ""
    if tun_mode:
        tun_interface_name = controller._ensure_xray_tun_contract(payload)
        # Keep mixed-in alive in TUN mode so the mixed port (10808) is always
        # reachable for manual app config and optional system proxy.

    api_port, inbound_tags = controller._ensure_xray_metrics_contract(payload, allocate_port=True)

    outbounds = payload.get("outbounds")
    has_proxy_outbound = False
    used_selected_node = False
    if isinstance(outbounds, list):
        for index, outbound in enumerate(outbounds):
            if not isinstance(outbound, dict) or outbound.get("tag") != "proxy":
                continue
            has_proxy_outbound = True
            if node is None:
                raise ValueError("В конфиге есть outbound tag `proxy`. Выберите сервер для запуска xray.")
            problem = controller._prepare_node_for_runtime(node)
            if problem:
                raise ValueError(problem)
            proxy_outbound = deepcopy(node.outbound)
            proxy_outbound["tag"] = "proxy"
            outbounds[index] = proxy_outbound
            used_selected_node = True
            break

    loop_prevention_interface = ""
    loop_prevention_patched_outbounds = 0
    if tun_mode:
        # autoOutboundsInterface in the TUN inbound tells xray to bind its own
        # sockets to the physical NIC natively — no need to patch each outbound.
        tun_has_auto_interface = _tun_inbound_has_auto_outbounds_interface(payload)
        needs_loop_patch = False
        if not tun_has_auto_interface and isinstance(outbounds, list):
            for outbound in outbounds:
                if not isinstance(outbound, dict):
                    continue
                tag = str(outbound.get("tag") or "").strip()
                protocol = str(outbound.get("protocol") or "").strip().lower()
                if tag in {APP_METRICS_API_TAG, "api"} or protocol in {"blackhole", "loopback", "dns"}:
                    continue
                if not controller._xray_outbound_is_loop_protected(outbound):
                    needs_loop_patch = True
                    break
        if needs_loop_patch:
            context = get_windows_default_route_context()
            if context is None:
                raise ValueError(
                    "Не удалось определить активный сетевой интерфейс для xray TUN loop prevention. "
                    "Либо укажите streamSettings.sockopt.interface/sendThrough в raw xray config, "
                    "либо используйте sing-box TUN."
                )
            loop_prevention_interface = context.interface_alias
            loop_prevention_patched_outbounds = controller._apply_xray_tun_loop_prevention(
                payload, loop_prevention_interface, context.source_ip
            )

    socks_port, http_port, _ = extract_xray_runtime_ports(payload)
    ping_host, ping_port = controller._infer_xray_ping_target(payload, node if used_selected_node else None)
    return XrayRuntimeConfig(
        config=payload,
        source_path=source_path,
        has_proxy_outbound=has_proxy_outbound,
        used_selected_node=used_selected_node,
        socks_port=socks_port,
        http_port=http_port,
        api_port=api_port,
        tun_interface_name=tun_interface_name,
        loop_prevention_interface=loop_prevention_interface,
        loop_prevention_patched_outbounds=loop_prevention_patched_outbounds,
        inbound_tags=inbound_tags,
        ping_host=ping_host,
        ping_port=ping_port,
    )
