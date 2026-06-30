"""Regression tests for TUN-mode catch-all routing.

Guards the fix for: in xray native-TUN mode the runtime contract must NOT rewrite
a config's catch-all ``{"port": "0-65535", "outboundTag": "direct"}`` rule into
``proxy`` when the TUN inbound carries ``autoOutboundsInterface`` — otherwise every
unmatched connection is forced through the proxy and the whole system gets
tunneled instead of only the explicitly routed apps/domains.

Run with: ``python -m unittest tests.test_xray_tun_catchall``
"""

from __future__ import annotations

import unittest

from xray_fluent.application.runtime_introspection import ensure_dict, ensure_list
from xray_fluent.application.xray_runtime_service import (
    _is_tun_direct_catchall,
    _redirect_tun_direct_catchalls,
    _tun_inbound_has_auto_outbounds_interface,
    ensure_xray_tun_contract,
)


class _FakeController:
    """Minimal stand-in providing the helpers ensure_xray_tun_contract relies on."""

    def __init__(self) -> None:
        self.logs: list[str] = []

    _ensure_dict = staticmethod(ensure_dict)
    _ensure_list = staticmethod(ensure_list)

    def _log(self, line: str) -> None:
        self.logs.append(line)


def _v2rayn_style_config() -> dict:
    """A trimmed v2rayN-style xray config: proxy a process, everything else direct."""
    return {
        "inbounds": [
            {
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "mixed",
            }
        ],
        "outbounds": [
            {"tag": "proxy", "protocol": "vless"},
            {"tag": "direct", "protocol": "freedom", "settings": {}},
        ],
        "routing": {
            "rules": [
                {"type": "field", "process": ["Discord.exe"], "outboundTag": "proxy"},
                {"type": "field", "port": "0-65535", "outboundTag": "direct"},
            ]
        },
    }


def _find_catchall(payload: dict) -> dict:
    for rule in payload["routing"]["rules"]:
        if str(rule.get("port") or "") == "0-65535":
            return rule
    raise AssertionError("catch-all port rule not found")


class IsTunDirectCatchallTests(unittest.TestCase):
    def test_recognizes_wide_direct_port_rule(self) -> None:
        self.assertTrue(
            _is_tun_direct_catchall({"port": "0-65535", "outboundTag": "direct"})
        )

    def test_rejects_proxy_outbound(self) -> None:
        self.assertFalse(
            _is_tun_direct_catchall({"port": "0-65535", "outboundTag": "proxy"})
        )

    def test_rejects_constrained_rule(self) -> None:
        # A wide port range that is narrowed by domain/ip/process/protocol is NOT
        # a catch-all and must never be flipped.
        for key, value in (
            ("domain", ["example.com"]),
            ("ip", ["1.1.1.1"]),
            ("process", ["Discord.exe"]),
            ("protocol", ["bittorrent"]),
        ):
            with self.subTest(constraint=key):
                self.assertFalse(
                    _is_tun_direct_catchall(
                        {"port": "0-65535", "outboundTag": "direct", key: value}
                    )
                )

    def test_rejects_narrow_port_range(self) -> None:
        self.assertFalse(
            _is_tun_direct_catchall({"port": "80-443", "outboundTag": "direct"})
        )


class AutoOutboundsInterfaceDetectionTests(unittest.TestCase):
    def test_detects_when_present(self) -> None:
        payload = {
            "inbounds": [
                {"protocol": "tun", "settings": {"autoOutboundsInterface": "auto"}}
            ]
        }
        self.assertTrue(_tun_inbound_has_auto_outbounds_interface(payload))

    def test_absent_without_field(self) -> None:
        payload = {"inbounds": [{"protocol": "tun", "settings": {}}]}
        self.assertFalse(_tun_inbound_has_auto_outbounds_interface(payload))

    def test_absent_without_tun_inbound(self) -> None:
        payload = {"inbounds": [{"protocol": "mixed"}]}
        self.assertFalse(_tun_inbound_has_auto_outbounds_interface(payload))


class RedirectCatchallLegacyTests(unittest.TestCase):
    """The raw redirect helper still flips catch-alls (used only on legacy builds
    without autoOutboundsInterface)."""

    def test_flips_and_counts(self) -> None:
        payload = _v2rayn_style_config()
        flipped = _redirect_tun_direct_catchalls(payload)
        self.assertEqual(flipped, 1)
        self.assertEqual(_find_catchall(payload)["outboundTag"], "proxy")


class EnsureTunContractTests(unittest.TestCase):
    def test_catchall_direct_preserved_under_auto_interface(self) -> None:
        controller = _FakeController()
        payload = _v2rayn_style_config()

        ensure_xray_tun_contract(controller, payload)

        # The contract must have enabled native interface binding...
        self.assertTrue(_tun_inbound_has_auto_outbounds_interface(payload))
        # ...and therefore left the catch-all as 'direct' (only Discord proxied).
        self.assertEqual(_find_catchall(payload)["outboundTag"], "direct")
        discord_rule = next(
            r for r in payload["routing"]["rules"] if r.get("process") == ["Discord.exe"]
        )
        self.assertEqual(discord_rule["outboundTag"], "proxy")

    def test_tun_sniffing_matches_v2rayn_proxy_inbound(self) -> None:
        # TUN routing must behave like v2rayN's mixed-in: sniff http/tls/quic and
        # routeOnly so process/domain rules decide the outbound while the original
        # destination IP is preserved (no re-resolve loop on direct traffic).
        controller = _FakeController()
        payload = _v2rayn_style_config()

        ensure_xray_tun_contract(controller, payload)

        tun = next(i for i in payload["inbounds"] if i.get("protocol") == "tun")
        sniffing = tun["sniffing"]
        self.assertTrue(sniffing["enabled"])
        self.assertEqual(sniffing["destOverride"], ["http", "tls", "quic"])
        self.assertTrue(sniffing["routeOnly"])

    def test_no_misleading_patch_log_emitted(self) -> None:
        controller = _FakeController()
        ensure_xray_tun_contract(controller, _v2rayn_style_config())
        self.assertFalse(
            any("auto-patched" in line for line in controller.logs),
            msg=f"unexpected catch-all patch log: {controller.logs}",
        )

    def test_tun_only_config_keeps_all_rules(self) -> None:
        # "Leave only TUN" scenario: a config with no mixed-in/proxy inbound, just
        # the routing rules. xray routing is not bound to a specific inbound, so the
        # contract must add the TUN inbound while preserving every rule — process
        # rules and the catch-all 'direct' — so per-app routing still applies.
        controller = _FakeController()
        payload = _v2rayn_style_config()
        payload["inbounds"] = [
            ib for ib in payload["inbounds"] if ib.get("protocol") != "mixed"
        ]
        self.assertEqual(payload["inbounds"], [])  # truly TUN-only to start

        ensure_xray_tun_contract(controller, payload)

        protocols = [ib.get("protocol") for ib in payload["inbounds"]]
        self.assertEqual(protocols, ["tun"])
        # Selected rules survive untouched: Discord still proxied, rest still direct.
        discord_rule = next(
            r for r in payload["routing"]["rules"] if r.get("process") == ["Discord.exe"]
        )
        self.assertEqual(discord_rule["outboundTag"], "proxy")
        self.assertEqual(_find_catchall(payload)["outboundTag"], "direct")


if __name__ == "__main__":
    unittest.main()
