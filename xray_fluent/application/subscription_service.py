from __future__ import annotations

import base64
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer

from ..country_flags import detect_country
from ..link_parser import parse_links_text, validate_node_outbound
from ..models import Subscription, utc_now_iso

if TYPE_CHECKING:
    from ..app_controller import AppController

_SUB_USER_AGENT = "v2rayN/6.0"


def _fetch_raw(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _SUB_USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
    content = raw.strip()
    # Try base64 decode (standard subscription format)
    try:
        padded = content + b"=" * ((4 - len(content) % 4) % 4)
        decoded = base64.b64decode(padded).decode("utf-8")
        # Sanity check: decoded should contain known schemes
        if any(decoded.lstrip().startswith(s) for s in ("vless://", "vmess://", "trojan://", "ss://")):
            return decoded
    except Exception:
        pass
    # Try urlsafe variant
    try:
        padded = content + b"=" * ((4 - len(content) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
        if any(decoded.lstrip().startswith(s) for s in ("vless://", "vmess://", "trojan://", "ss://")):
            return decoded
    except Exception:
        pass
    # Fall back to plain text
    return content.decode("utf-8", errors="replace")


def import_subscription(controller: AppController, url: str, name: str) -> tuple[int, list[str]]:
    """Fetch subscription URL, parse nodes, create Subscription record. Returns (added, errors)."""
    try:
        text = _fetch_raw(url)
    except urllib.error.URLError as e:
        return 0, [f"Ошибка загрузки: {e.reason}"]
    except Exception as e:
        return 0, [f"Ошибка загрузки: {e}"]

    nodes, errors = parse_links_text(text)
    if not nodes:
        return 0, errors or ["Подписка не содержит серверов"]

    sub = Subscription(name=name, url=url, last_updated_at=utc_now_iso())
    controller.state.subscriptions.append(sub)

    existing_links = {node.link for node in controller.state.nodes}
    max_order = max((node.sort_order for node in controller.state.nodes), default=0)
    added = 0
    for node in nodes:
        problem = validate_node_outbound(node)
        if problem:
            errors.append(problem)
            continue
        if node.link in existing_links:
            continue
        if not node.country_code:
            node.country_code = detect_country(node.name, node.server)
        max_order += 1
        node.sort_order = max_order
        node.subscription_id = sub.id
        node.group = sub.name
        controller.state.nodes.append(node)
        existing_links.add(node.link)
        added += 1

    if added and not controller.state.selected_node_id:
        controller.state.selected_node_id = controller.state.nodes[0].id

    controller.subscriptions_changed.emit(controller.state.subscriptions)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    QTimer.singleShot(500, controller._start_country_ip_resolution)

    return added, errors


def update_subscription(controller: AppController, sub_id: str) -> tuple[int, int, list[str]]:
    """Re-fetch subscription, add new nodes, remove deleted ones. Returns (added, removed, errors)."""
    sub = next((s for s in controller.state.subscriptions if s.id == sub_id), None)
    if sub is None:
        return 0, 0, ["Подписка не найдена"]

    try:
        text = _fetch_raw(sub.url)
    except urllib.error.URLError as e:
        return 0, 0, [f"Ошибка загрузки: {e.reason}"]
    except Exception as e:
        return 0, 0, [f"Ошибка загрузки: {e}"]

    nodes, errors = parse_links_text(text)
    fresh_links = {node.link for node in nodes}

    # Remove nodes that are in this subscription but no longer in the feed
    old_sub_nodes = [n for n in controller.state.nodes if n.subscription_id == sub_id]
    removed_ids = {n.id for n in old_sub_nodes if n.link not in fresh_links}
    removed_selected = controller.state.selected_node_id in removed_ids
    controller.state.nodes = [n for n in controller.state.nodes if n.id not in removed_ids]
    removed = len(removed_ids)

    existing_links = {node.link for node in controller.state.nodes}
    max_order = max((node.sort_order for node in controller.state.nodes), default=0)
    added = 0
    for node in nodes:
        problem = validate_node_outbound(node)
        if problem:
            errors.append(problem)
            continue
        if node.link in existing_links:
            continue
        if not node.country_code:
            node.country_code = detect_country(node.name, node.server)
        max_order += 1
        node.sort_order = max_order
        node.subscription_id = sub_id
        node.group = sub.name
        controller.state.nodes.append(node)
        existing_links.add(node.link)
        added += 1

    sub.last_updated_at = utc_now_iso()

    if removed_selected:
        controller.state.selected_node_id = controller.state.nodes[0].id if controller.state.nodes else None

    controller.subscriptions_changed.emit(controller.state.subscriptions)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    QTimer.singleShot(500, controller._start_country_ip_resolution)

    return added, removed, errors


def remove_subscription(controller: AppController, sub_id: str) -> None:
    """Remove a subscription and all nodes belonging to it."""
    removed_ids = {n.id for n in controller.state.nodes if n.subscription_id == sub_id}
    removed_selected = controller.state.selected_node_id in removed_ids
    controller.state.nodes = [n for n in controller.state.nodes if n.id not in removed_ids]
    controller.state.subscriptions = [s for s in controller.state.subscriptions if s.id != sub_id]

    if removed_selected:
        controller.state.selected_node_id = controller.state.nodes[0].id if controller.state.nodes else None

    controller.subscriptions_changed.emit(controller.state.subscriptions)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()


def rename_subscription(controller: AppController, sub_id: str, new_name: str) -> bool:
    sub = next((s for s in controller.state.subscriptions if s.id == sub_id), None)
    if sub is None:
        return False
    old_name = sub.name
    sub.name = new_name
    for node in controller.state.nodes:
        if node.subscription_id == sub_id and node.group == old_name:
            node.group = new_name
    controller.subscriptions_changed.emit(controller.state.subscriptions)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()
    return True
