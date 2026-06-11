from __future__ import annotations

import ntpath
import subprocess
from copy import deepcopy
from functools import lru_cache
from ipaddress import ip_network
from typing import Any

from ...constants import (
    DEFAULT_HTTP_PORT,
    DEFAULT_SOCKS_PORT,
    PROXY_HOST,
    ROUTING_DIRECT,
    ROUTING_GLOBAL,
    ROUTING_RULE,
    DEFAULT_XRAY_STATS_API_PORT,
)
from ...models import AppSettings, Node, RoutingSettings
from ...process_presets import PROCESS_PRESETS_BY_ID
from ...service_presets import SERVICE_PRESETS_BY_ID


def _normalize_loglevel(value: str) -> str:
    normalized = value.lower().strip()
    if normalized == "warn":
        return "warning"
    if normalized in {"debug", "info", "warning", "error", "none"}:
        return normalized
    return "warning"


def _split_rule_items(items: list[str]) -> tuple[list[str], list[str]]:
    domains: list[str] = []
    ips: list[str] = []
    for raw in items:
        value = raw.strip()
        if not value:
            continue

        if value.startswith(("domain:", "full:", "regexp:", "keyword:", "geosite:", "ext:")):
            domains.append(value)
            continue
        if value.startswith(("geoip:", "ip:")):
            ips.append(value)
            continue

        try:
            ip_network(value, strict=False)
            ips.append(value)
            continue
        except ValueError:
            pass

        domains.append(f"domain:{value}")

    return domains, ips


def _append_domain_ip_rule(rules: list[dict[str, Any]], items: list[str], outbound_tag: str) -> None:
    domains, ips = _split_rule_items(items)
    if domains:
        rules.append(
            {
                "type": "field",
                "domain": domains,
                "outboundTag": outbound_tag,
            }
        )
    if ips:
        rules.append(
            {
                "type": "field",
                "ip": ips,
                "outboundTag": outbound_tag,
            }
        )


def _resolve_xray_process_name(rule: dict[str, str]) -> str:
    value = str(rule.get("process", "")).strip()
    if not value:
        return ""
    match = str(rule.get("match", "")).strip().lower()
    if match == "path_regex":
        return ""
    if match == "path" or "\\" in value or "/" in value or (len(value) > 1 and value[1] == ":"):
        return ntpath.basename(value)
    return value


@lru_cache(maxsize=1)
def _get_uwp_process_names() -> tuple[str, ...]:
    """Return executable basenames of all installed non-framework UWP apps."""
    script = (
        "Get-AppxPackage | Where-Object { $_.IsFramework -eq $false } | ForEach-Object {"
        "  $m = Join-Path $_.InstallLocation 'AppxManifest.xml';"
        "  if (Test-Path $m) { try {"
        "    [xml]$x = [xml](Get-Content $m -Raw -ErrorAction Stop);"
        "    $x.Package.Applications.Application | ForEach-Object {"
        "      if ($_.Executable) { Split-Path $_.Executable -Leaf }"
        "    }"
        "  } catch {} }"
        "} | Sort-Object -Unique"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    except Exception:
        pass
    return ()


def build_xray_config(
    node: Node,
    routing: RoutingSettings,
    settings: AppSettings,
    api_port: int = 0,
    *,
    socks_port: int = DEFAULT_SOCKS_PORT,
    http_port: int = DEFAULT_HTTP_PORT,
) -> dict[str, Any]:
    if not api_port:
        api_port = DEFAULT_XRAY_STATS_API_PORT
    proxy_outbound = deepcopy(node.outbound)
    proxy_outbound["tag"] = "proxy"

    routing_rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]

    if routing.bypass_lan:
        routing_rules.append(
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "direct",
            }
        )
        routing_rules.append(
            {
                "type": "field",
                "domain": ["geosite:private"],
                "outboundTag": "direct",
            }
        )

    # Process rules — work in both system-proxy and TUN mode
    for pr in routing.process_rules:
        name = _resolve_xray_process_name(pr)
        action = pr.get("action", "direct")
        if name:
            routing_rules.append({
                "type": "field",
                "process": [name],
                "network": "tcp,udp",
                "outboundTag": action if action in ("direct", "proxy", "block") else "direct",
            })

    # Process preset groups (telegram, discord, windows_system, etc.)
    for preset_id, action in routing.process_preset_routes.items():
        preset = PROCESS_PRESETS_BY_ID.get(preset_id)
        if not preset:
            continue
        tag = action if action in ("direct", "proxy", "block") else "direct"
        routing_rules.append({
            "type": "field",
            "process": list(preset.processes),
            "network": "tcp,udp",
            "outboundTag": tag,
        })

    # UWP apps (TUN mode only) — enumerate installed Microsoft Store apps and proxy them
    if settings.tun_mode and routing.tun_route_uwp:
        uwp_names = list(_get_uwp_process_names())
        if uwp_names:
            routing_rules.append({
                "type": "field",
                "process": uwp_names,
                "network": "tcp,udp",
                "outboundTag": "proxy",
            })

    # Merge service preset domains
    service_direct: list[str] = []
    service_proxy: list[str] = []
    service_block: list[str] = []
    for svc_id, action in routing.service_routes.items():
        preset = SERVICE_PRESETS_BY_ID.get(svc_id)
        if not preset:
            continue
        if action == "direct":
            service_direct.extend(preset.domains)
        elif action == "block":
            service_block.extend(preset.domains)
        else:
            service_proxy.extend(preset.domains)
    _append_domain_ip_rule(routing_rules, service_proxy, "proxy")
    _append_domain_ip_rule(routing_rules, service_direct, "direct")
    _append_domain_ip_rule(routing_rules, service_block, "block")
    _append_domain_ip_rule(routing_rules, routing.direct_domains, "direct")
    _append_domain_ip_rule(routing_rules, routing.block_domains, "block")
    _append_domain_ip_rule(routing_rules, routing.proxy_domains, "proxy")

    # Catch-all rule:
    # In TUN mode: use tun_default_outbound (only listed processes + UWP go to proxy,
    #              everything else goes where tun_default_outbound points)
    # In system-proxy mode: use routing mode (GLOBAL/RULE/DIRECT)
    if settings.tun_mode:
        catch_all = routing.tun_default_outbound if routing.tun_default_outbound in ("proxy", "direct") else "direct"
        routing_rules.append({"type": "field", "network": "tcp,udp", "outboundTag": catch_all})
    else:
        mode = routing.mode
        if mode == ROUTING_GLOBAL:
            routing_rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
        elif mode == ROUTING_DIRECT:
            routing_rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})
        else:
            routing_rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})

    config: dict[str, Any] = {
        "log": {
            "loglevel": _normalize_loglevel(settings.log_level),
        },
        "inbounds": [
            {
                "tag": "mixed-in",
                "listen": PROXY_HOST,
                "port": int(socks_port),
                "protocol": "mixed",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            },
            {
                "tag": "api",
                "listen": PROXY_HOST,
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": PROXY_HOST,
                },
            },
        ],
        "outbounds": [
            proxy_outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            },
            {
                "tag": "api",
                "protocol": "freedom",
                "settings": {},
            },
        ],
        "policy": {
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            }
        },
        "stats": {},
        "api": {
            "tag": "api",
            "services": ["StatsService"],
        },
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules,
        },
    }

    if routing.dns_mode == "builtin":
        config["dns"] = {
            "servers": [
                "1.1.1.1",
                "8.8.8.8",
                "localhost",
            ],
            "queryStrategy": "UseIP",
        }

    return config
