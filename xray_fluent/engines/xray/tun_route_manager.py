from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field

from PyQt6.QtCore import QObject, pyqtSignal

from ...constants import XRAY_TUN_DEFAULT_ADDRESS, XRAY_TUN_DEFAULT_INTERFACE_NAME
from ...subprocess_utils import CREATE_NO_WINDOW, result_output_text, run_text_pumped, sleep_with_events

# Private IP ranges — traffic to these bypasses TUN via more-specific connected routes
# on the physical interface. We add explicit routes so xray's direct outbound to LAN
# also takes the physical path without relying on sockopt.interface.
_LAN_BYPASS_ROUTES: list[tuple[str, str]] = [
    ("10.0.0.0",     "255.0.0.0"),
    ("172.16.0.0",   "255.240.0.0"),
    ("192.168.0.0",  "255.255.0.0"),
    ("169.254.0.0",  "255.255.0.0"),
    ("100.64.0.0",   "255.192.0.0"),   # CGNAT
]


def _is_valid_ipv4(addr: str) -> bool:
    try:
        ipaddress.IPv4Address(addr)
        return True
    except ValueError:
        return False


def _powershell_string_literal(value: str) -> str:
    return value.replace("'", "''")


# ──────────────────────────────────────────────────────────────────────────────
# Context returned by get_windows_default_route_context()
# ──────────────────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class WindowsDefaultRouteContext:
    interface_alias: str
    source_ip: str          # IPv4 address of the physical interface


@dataclass(slots=True)
class _TunInterface:
    index: int
    ipv4: str               # e.g. "198.18.0.1"
    ipv6: str               # e.g. "fd00::1" or ""


def get_windows_default_route_context() -> WindowsDefaultRouteContext | None:
    """Return the physical interface alias and IP before TUN routes are installed."""
    if os.name != "nt":
        return None
    script = (
        "$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "| Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; "
        "if (-not $route) { exit 1 }; "
        "$addr = Get-NetIPAddress -InterfaceAlias $route.InterfaceAlias -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue "
        "| Where-Object { $_.PrefixOrigin -ne 'WellKnown' } "
        "| Select-Object -First 1; "
        "@{ interface_alias = $route.InterfaceAlias; source_ip = ($addr.IPAddress) } | ConvertTo-Json -Compress"
    )
    try:
        result = run_text_pumped(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            timeout=6,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result_output_text(result) or "{}")
    except json.JSONDecodeError:
        return None
    alias = str(payload.get("interface_alias") or "").strip()
    src = str(payload.get("source_ip") or "").strip()
    if not alias:
        return None
    return WindowsDefaultRouteContext(interface_alias=alias, source_ip=src)


# ──────────────────────────────────────────────────────────────────────────────
# Route manager
# ──────────────────────────────────────────────────────────────────────────────

class XrayTunRouteManager(QObject):
    """Manages Windows routing table entries for the xray native-TUN engine.

    Strategy (works on ALL xray builds):
    • Split-tunnel with two /1 routes (0.0.0.0/1 + 128.0.0.0/1) — more specific
      than the physical default /0 so they win even without metric tricks.
    • Explicit /32 bypass for the VPN server (proxy outbound destination).
    • Explicit /24-/8 bypass routes for private LAN ranges (direct outbound).
    • If xray has autoRoute=true and set up its own routes already, we still add
      our bypasses but skip adding the duplicate /1 defaults.

    We intentionally do NOT rely on sockopt.interface or sendThrough because their
    effectiveness varies across xray builds on Windows.
    """

    log_received = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._tun_name = XRAY_TUN_DEFAULT_INTERFACE_NAME
        self._tun_idx = 0
        self._tun_gw = ""           # TUN interface's own IP (nexthop for /1 routes)
        self._orig_gw = ""          # physical gateway
        self._server_ip = ""        # VPN server IP (for cleanup)
        self._lan_routes_added: list[tuple[str, str, str]] = []   # (dest, mask, gw)
        self._split_routes_added: bool = False
        self._ipv6_default_added: bool = False

    # ── public API ────────────────────────────────────────────────────────────

    def setup(self, tun_interface_name: str, server_ip: str = "") -> bool:
        if os.name != "nt":
            return True

        self.cleanup()
        self._tun_name = (str(tun_interface_name or "").strip()
                          or XRAY_TUN_DEFAULT_INTERFACE_NAME)

        # 1. Wait for xray to create the TUN interface and assign it an IP.
        iface = self._wait_for_tun_interface(self._tun_name)
        if iface is None:
            self._log(f"TUN interface '{self._tun_name}' did not appear (adapter not found within timeout)")
            return False

        self._tun_idx = iface.index
        # xray 26.x may assign IP via internal TUN stack, not Windows IP Helper;
        # fall back to the configured gateway address so route skip logic still works.
        self._tun_gw = iface.ipv4 or XRAY_TUN_DEFAULT_ADDRESS.split("/")[0]

        # 2. Capture the physical gateway using Get-NetRoute with TUN index filter.
        #    This works even when xray's autoSystemRoutingTable has already installed
        #    a 0.0.0.0/0 route through TUN (we exclude it by interface index).
        self._orig_gw = self._get_original_gateway()
        if not self._orig_gw:
            self._log("could not determine physical gateway — aborting TUN route setup")
            return False

        # 3. VPN server /32 bypass (must exist BEFORE default routes).
        if server_ip and _is_valid_ipv4(server_ip):
            self._add_server_bypass(server_ip, self._orig_gw)

        # 4. LAN bypass routes.
        self._add_lan_bypasses(self._orig_gw)

        # 5. TUN default routes — only if xray's autoSystemRoutingTable hasn't added them.
        if self._tun_has_default_routes():
            self._log("xray autoSystemRoutingTable already installed TUN default routes — skipping manual add")
        else:
            # Remove stale /1 or /0 routes from a crashed previous session before adding ours.
            self._delete_stale_tun_routes()
            ok = self._add_split_routes()
            if not ok:
                self.cleanup()
                return False
            self._split_routes_added = True

        # 6. Optional IPv6 default via TUN.
        if iface.ipv6:
            self._add_ipv6_default(iface.ipv6)

        return True

    def cleanup(self) -> None:
        if os.name != "nt":
            return

        # Remove server bypass.
        if self._server_ip and self._orig_gw:
            self._run_best(["route", "delete", self._server_ip,
                            "mask", "255.255.255.255", self._orig_gw])
        self._server_ip = ""

        # Remove LAN bypasses we added.
        for dest, mask, gw in self._lan_routes_added:
            self._run_best(["route", "delete", dest, "mask", mask, gw])
        self._lan_routes_added = []

        # Remove split /1 routes (only if WE added them).
        if self._split_routes_added and self._tun_idx > 0:
            self._run_best(["netsh", "interface", "ipv4", "delete", "route",
                            "0.0.0.0/1", f"interface={self._tun_idx}"])
            self._run_best(["netsh", "interface", "ipv4", "delete", "route",
                            "128.0.0.0/1", f"interface={self._tun_idx}"])
        self._split_routes_added = False

        # Remove IPv6 default.
        if self._ipv6_default_added and self._tun_idx > 0:
            self._run_best([
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"Remove-NetRoute -DestinationPrefix '::/0' -InterfaceIndex {self._tun_idx} "
                "-AddressFamily IPv6 -Confirm:$false -ErrorAction SilentlyContinue | Out-Null",
            ])
        self._ipv6_default_added = False

        self._tun_idx = 0
        self._tun_gw = ""
        self._orig_gw = ""

    # ── private helpers ───────────────────────────────────────────────────────

    def _wait_for_tun_interface(self, name: str, max_sec: float = 12.0) -> _TunInterface | None:
        elapsed = 0.0
        while elapsed < max_sec:
            iface = self._read_tun_interface(name)
            if iface is not None:
                return iface
            sleep_with_events(0.5)
            elapsed += 0.5
        return None

    @staticmethod
    def _read_tun_interface(name: str) -> _TunInterface | None:
        """Detect the TUN adapter by name.

        xray 26.x (Wintun) assigns the IP address via its internal TUN stack,
        so Get-NetIPAddress may not see it. We use Get-NetAdapter as the primary
        check (just need the adapter index) and fall back to Get-NetIPAddress for
        the IP when available.
        """
        escaped = _powershell_string_literal(name)
        # All parts are f-strings so {{ → { and }} → } in the generated PS script.
        script = (
            f"$a = Get-NetAdapter -Name '{escaped}' -ErrorAction SilentlyContinue; "
            f"if (-not $a) {{ exit 1 }}; "
            f"$v4 = Get-NetIPAddress -InterfaceAlias '{escaped}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue "
            f"| Where-Object {{ $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' }} "
            f"| Select-Object -First 1; "
            f"$v6 = Get-NetIPAddress -InterfaceAlias '{escaped}' -AddressFamily IPv6 "
            f"-ErrorAction SilentlyContinue "
            f"| Where-Object {{ $_.IPAddress -notlike 'fe80::*' }} "
            f"| Select-Object -First 1; "
            f"@{{ idx = $a.InterfaceIndex; v4 = ($v4.IPAddress); v6 = ($v6.IPAddress) }} "
            f"| ConvertTo-Json -Compress"
        )
        try:
            result = run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=5, creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            return None
        if result.returncode != 0:
            return None
        try:
            payload = json.loads(result_output_text(result) or "{}")
        except json.JSONDecodeError:
            return None
        idx = int(payload.get("idx") or 0)
        ipv4 = str(payload.get("v4") or "").strip()
        ipv6 = str(payload.get("v6") or "").strip()
        if idx <= 0:
            return None
        return _TunInterface(index=idx, ipv4=ipv4, ipv6=ipv6)

    def _delete_stale_tun_routes(self) -> None:
        """Remove leftover TUN routes from a previous session."""
        if self._tun_idx <= 0:
            return
        for prefix in ("0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"):
            self._run_best(["netsh", "interface", "ipv4", "delete", "route",
                            prefix, f"interface={self._tun_idx}"])

    def _get_original_gateway(self) -> str:
        """Read the physical default gateway, excluding any route via TUN."""
        # Use Get-NetRoute with interface index filter so we always get the
        # physical uplink even when xray's autoSystemRoutingTable has added
        # a 0.0.0.0/0 route through the TUN adapter.
        try:
            script = (
                f"$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
                f"-ErrorAction SilentlyContinue "
                f"| Where-Object {{ $_.InterfaceIndex -ne {self._tun_idx} }} "
                "| Sort-Object RouteMetric, InterfaceMetric "
                "| Select-Object -First 1; "
                "if (-not $r) { exit 1 }; "
                "Write-Output $r.NextHop"
            )
            result = run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=6, creationflags=CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                gw = result_output_text(result).strip()
                if gw and gw not in {"0.0.0.0", "::"}:
                    return gw
        except Exception:
            pass
        # Fallback: parse `route print` text output
        try:
            result = run_text_pumped(
                ["cmd", "/c", "route", "print", "0.0.0.0"],
                timeout=5, creationflags=CREATE_NO_WINDOW,
            )
            for line in result_output_text(result).splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if gw != self._tun_gw and gw not in {"0.0.0.0", "::"}:
                        return gw
        except Exception:
            pass
        return ""

    def _tun_has_default_routes(self) -> bool:
        """Return True if xray autoRoute already installed /1 or /0 routes via TUN."""
        if self._tun_idx <= 0:
            return False
        try:
            script = (
                f"$r = Get-NetRoute -InterfaceIndex {self._tun_idx} -AddressFamily IPv4 "
                f"-ErrorAction SilentlyContinue "
                f"| Where-Object {{ $_.DestinationPrefix -in ('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') }}; "
                f"if ($r) {{ 'yes' }} else {{ 'no' }}"
            )
            result = run_text_pumped(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=5, creationflags=CREATE_NO_WINDOW,
            )
            return "yes" in result_output_text(result).lower()
        except Exception:
            return False

    def _add_server_bypass(self, server_ip: str, gw: str) -> None:
        self._run_best(["route", "delete", server_ip, "mask", "255.255.255.255"])
        r = self._run_logged(["route", "add", server_ip, "mask", "255.255.255.255",
                              gw, "metric", "1"])
        if r.returncode == 0:
            self._server_ip = server_ip
        else:
            self._log(f"warning: failed to add server bypass for {server_ip}")

    def _add_lan_bypasses(self, gw: str) -> None:
        for dest, mask in _LAN_BYPASS_ROUTES:
            self._run_best(["route", "delete", dest, "mask", mask])
            r = self._run_logged(["route", "add", dest, "mask", mask, gw, "metric", "1"])
            if r.returncode == 0:
                self._lan_routes_added.append((dest, mask, gw))

    def _add_split_routes(self) -> bool:
        """Add 0.0.0.0/1 + 128.0.0.0/1 via TUN (split default routes)."""
        for prefix in ("0.0.0.0/1", "128.0.0.0/1"):
            r = self._run_logged([
                "netsh", "interface", "ipv4", "add", "route",
                prefix, f"interface={self._tun_idx}",
                f"nexthop={self._tun_gw}", "metric=0",
            ])
            if r.returncode != 0:
                self._log(f"failed to add TUN route {prefix}")
                return False
        return True

    def _add_ipv6_default(self, _ipv6_addr: str) -> None:
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            f"$ErrorActionPreference='Stop'; "
            f"New-NetRoute -DestinationPrefix '::/0' -InterfaceIndex {self._tun_idx} "
            "-AddressFamily IPv6 -NextHop '::' -RouteMetric 0 -PolicyStore ActiveStore | Out-Null",
        ]
        r = self._run_logged(cmd)
        if r.returncode == 0:
            self._ipv6_default_added = True

    def _run_logged(self, command: list[str]):
        result = run_text_pumped(command, timeout=5, creationflags=CREATE_NO_WINDOW)
        out = result_output_text(result).strip()
        self.log_received.emit(f"[xray-tun] {' '.join(command)} → rc={result.returncode}")
        if out:
            self.log_received.emit(f"[xray-tun] {out}")
        return result

    def _run_best(self, command: list[str]) -> None:
        try:
            self._run_logged(command)
        except Exception:
            pass

    def _log(self, msg: str) -> None:
        self.log_received.emit(f"[xray-tun] {msg}")
