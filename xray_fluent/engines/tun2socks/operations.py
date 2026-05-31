from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ...constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT
from ..xray.config_builder import build_xray_config
from ..xray.tun_route_manager import get_windows_default_route_context

if TYPE_CHECKING:
    from ...app_controller import AppController
    from ...models import Node


@dataclass(slots=True)
class Tun2SocksStartResult:
    session_label: str


def _is_loop_protected(outbound: dict) -> bool:
    send_through = str(outbound.get("sendThrough") or "").strip()
    if send_through and send_through not in {"0.0.0.0", "::"}:
        return True
    sockopt = (outbound.get("streamSettings") or {})
    if isinstance(sockopt, dict):
        sockopt = (sockopt.get("sockopt") or {})
    return bool(isinstance(sockopt, dict) and str(sockopt.get("interface") or "").strip())


def _apply_tun2socks_loop_prevention(config: dict) -> None:
    """Add sendThrough to all xray outbounds so direct traffic doesn't loop through TUN.

    In tun2socks mode xray runs as a plain SOCKS5 proxy on localhost. Any outbound
    that uses the system routing table (freedom/direct) will have its packets
    redirected through the TUN if the default route points there — creating an
    infinite loop that pins the CPU at 100%.  Binding to the physical interface's
    source IP breaks the loop: Windows must route those packets via the interface
    that owns the IP, regardless of the routing table.
    """
    context = get_windows_default_route_context()
    if context is None or not context.interface_alias:
        return
    for outbound in config.get("outbounds", []):
        if not isinstance(outbound, dict):
            continue
        protocol = str(outbound.get("protocol") or "").strip().lower()
        if protocol in {"blackhole", "loopback", "dns"}:
            continue
        if _is_loop_protected(outbound):
            continue
        # sockopt.interface → IP_UNICAST_IF (primary: overrides routing table).
        # sendThrough → bind() by source IP (secondary: works when IP_UNICAST_IF
        # is not available or ignored by this xray build).
        stream_settings = outbound.setdefault("streamSettings", {})
        sockopt = stream_settings.setdefault("sockopt", {})
        sockopt["interface"] = context.interface_alias
        if context.source_ip and context.source_ip not in {"0.0.0.0", "::"}:
            outbound["sendThrough"] = context.source_ip


def _build_tun2socks_xray_config(node: Node, controller: AppController) -> dict:
    config = build_xray_config(
        node,
        controller.state.routing,
        controller.state.settings,
        api_port=controller._xray_api_port,
        socks_port=DEFAULT_SOCKS_PORT,
        http_port=DEFAULT_HTTP_PORT,
    )
    config["log"] = {"loglevel": "error"}
    _apply_tun2socks_loop_prevention(config)
    return config


def start_tun(
    controller: AppController,
    node: Node,
    *,
    prev_active_core: str,
) -> Tun2SocksStartResult | None:
    controller._active_core = "tun2socks"
    # Build xray config with always-on mixed-in (no stripping).
    # tun2socks connects to the mixed port (10808) directly — no auth needed
    # since mixed-in binds to 127.0.0.1 (localhost only).
    config = _build_tun2socks_xray_config(node, controller)
    if not controller.xray.start(controller.state.settings.xray_path, config):
        controller._log("[tun] xray start failed")
        controller._active_core = prev_active_core
        return None
    controller._set_connection_status("starting", "Xray запущен. Создание TUN адаптера...", level="info")

    socks_port = DEFAULT_SOCKS_PORT
    controller._log(f"[tun] starting tun2socks -> SOCKS 127.0.0.1:{socks_port}")
    tun_ok = controller.tun2socks.start(socks_port, server_ip=node.server)
    controller._log(f"[tun] tun2socks start result: {tun_ok}")
    if not tun_ok:
        controller.xray.stop()
        controller._set_connection_status(
            "error",
            "Не удалось создать TUN адаптер. Проверьте наличие tun2socks и wintun.dll в core/.",
            level="error",
        )
        controller._active_core = prev_active_core
        return None
    return Tun2SocksStartResult(session_label=node.name)


def hot_swap(controller: AppController, reason: str, node: Node) -> bool:
    controller._switching = True
    try:
        problem = controller._prepare_node_for_runtime(node)
        if problem:
            controller._set_connection_status("error", problem, level="error")
            return False
        controller._log(f"[hot-swap] {reason} — restarting xray only, tun2socks stays up")
        controller._set_connection_status("starting", f"Переключение на {node.name}...", level="info")
        controller.xray.stop()
        config = _build_tun2socks_xray_config(node, controller)
        ok = controller.xray.start(controller.state.settings.xray_path, config)
        if ok:
            node.last_used_at = datetime.now(timezone.utc).isoformat()
            controller._capture_active_session(
                node,
                tun=True,
                core="tun2socks",
                api_port=controller._xray_api_port,
                xray_inbound_tags=("mixed-in", "socks-in", "http-in"),
                ping_host=node.server,
                ping_port=node.port,
            )
            controller._set_connection_status("running", f"Переключено: {node.name} (TUN)", level="success")
            controller.save()
        else:
            controller._log("[hot-swap] xray restart failed")
            controller._set_connection_status("error", "Не удалось переключить сервер, подключение остановлено", level="error")
            controller._handle_unexpected_disconnect()
        return ok
    finally:
        controller._switching = False
        controller._auto_switch_transitioning = False
        _, controller.connected = controller._refresh_connected_state()
        controller.connection_changed.emit(controller.connected)
        if controller.connected:
            controller._start_metrics_worker()
        else:
            controller._stop_metrics_worker()
