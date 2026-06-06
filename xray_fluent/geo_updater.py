"""Geo-files updater: downloads geoip.dat / geosite.dat from runetfreedom/russia-v2ray-rules-dat."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import BASE_DIR, GEO_GITHUB_RELEASES_API
from .http_utils import urlopen

import json
import re


USER_AGENT = "ZapretKVN/0.4"
GEO_TARGET_DIR = BASE_DIR / "core"

# Files we want to download from the release
GEO_ASSET_NAMES = ("geoip.dat", "geosite.dat", "geoip-only-cn-private.dat")


@dataclass(slots=True)
class GeoUpdateResult:
    status: str  # up_to_date | available | updated | error
    message: str
    current_version: str
    latest_version: str
    updated: bool = False


def _request_json(url: str) -> object:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _pick_release(releases: list[dict], allow_prerelease: bool) -> dict | None:
    for release in releases:
        is_pre = bool(release.get("prerelease"))
        if is_pre and not allow_prerelease:
            continue
        if release.get("draft"):
            continue
        return release
    return None


def _find_asset(release: dict, name: str) -> dict | None:
    for asset in release.get("assets", []):
        if str(asset.get("name") or "").lower() == name.lower():
            return asset
    return None


def _extract_digest(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1].strip()
    match = re.search(r"([a-f0-9]{64})", text)
    return match.group(1) if match else ""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _download_file(url: str, dest: Path, on_progress=None) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=120) as response:
        total = int(response.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if on_progress and total > 0:
                    on_progress(downloaded, total)


def resolve_geo_release(allow_prerelease: bool = False) -> dict | None:
    payload = _request_json(GEO_GITHUB_RELEASES_API)
    if not isinstance(payload, list):
        return None
    releases = [r for r in payload if isinstance(r, dict)]
    return _pick_release(releases, allow_prerelease)


def check_and_update_geo(
    installed_version: str,
    allow_prerelease: bool = False,
    apply_update: bool = False,
    target_dir: Path | None = None,
    on_progress=None,
) -> GeoUpdateResult:
    if target_dir is None:
        target_dir = GEO_TARGET_DIR

    try:
        release = resolve_geo_release(allow_prerelease)
    except Exception as exc:
        return GeoUpdateResult(
            status="error",
            message=f"Ошибка получения информации о релизе: {exc}",
            current_version=installed_version,
            latest_version="",
        )

    if not release:
        return GeoUpdateResult(
            status="error",
            message="Релиз geo-файлов не найден",
            current_version=installed_version,
            latest_version="",
        )

    latest_version = str(release.get("tag_name") or release.get("name") or "")

    # If versions match and all local files exist, nothing to do
    all_exist = all((target_dir / name).exists() for name in ("geoip.dat", "geosite.dat"))
    if installed_version and installed_version == latest_version and all_exist:
        return GeoUpdateResult(
            status="up_to_date",
            message=f"Geo-файлы актуальны ({latest_version})",
            current_version=installed_version,
            latest_version=latest_version,
        )

    if not apply_update:
        return GeoUpdateResult(
            status="available",
            message=f"Доступно обновление geo-файлов: {latest_version}",
            current_version=installed_version,
            latest_version=latest_version,
        )

    # Download all available assets
    assets_to_download: list[tuple[str, str]] = []  # (name, url)
    for name in GEO_ASSET_NAMES:
        asset = _find_asset(release, name)
        if asset:
            url = str(asset.get("browser_download_url") or "")
            if url:
                assets_to_download.append((name, url))

    if not assets_to_download:
        return GeoUpdateResult(
            status="error",
            message="В релизе не найдены geo-файлы (.dat)",
            current_version=installed_version,
            latest_version=latest_version,
        )

    total_assets = len(assets_to_download)
    with tempfile.TemporaryDirectory(prefix="geo_update_") as tmp_str:
        tmp = Path(tmp_str)
        staged: list[tuple[Path, Path]] = []  # (dest, staged_file)

        for idx, (name, url) in enumerate(assets_to_download):
            staged_file = tmp / name

            def _progress(downloaded: int, total: int, i: int = idx) -> None:
                if on_progress and total > 0:
                    base = int(i * 100 / total_assets)
                    part = int(downloaded * 100 / total / total_assets)
                    on_progress(base + part)

            try:
                _download_file(url, staged_file, on_progress=_progress)
            except Exception as exc:
                return GeoUpdateResult(
                    status="error",
                    message=f"Ошибка загрузки {name}: {exc}",
                    current_version=installed_version,
                    latest_version=latest_version,
                )
            staged.append((target_dir / name, staged_file))

        # Atomic replace with backup
        backups: list[tuple[Path, Path]] = []
        try:
            for dest, src in staged:
                if dest.exists():
                    bak = tmp / (dest.name + ".bak")
                    shutil.copy2(dest, bak)
                    backups.append((dest, bak))
                shutil.copy2(src, dest)
        except Exception as exc:
            # Rollback
            for dest, bak in reversed(backups):
                try:
                    shutil.copy2(bak, dest)
                except Exception:
                    pass
            return GeoUpdateResult(
                status="error",
                message=f"Ошибка установки geo-файлов: {exc}",
                current_version=installed_version,
                latest_version=latest_version,
            )

    if on_progress:
        on_progress(100)

    return GeoUpdateResult(
        status="updated",
        message=f"Geo-файлы обновлены до {latest_version}",
        current_version=installed_version,
        latest_version=latest_version,
        updated=True,
    )


class GeoUpdateWorker(QThread):
    done = pyqtSignal(object)       # GeoUpdateResult
    progress = pyqtSignal(int)      # 0-100

    def __init__(
        self,
        installed_version: str,
        allow_prerelease: bool,
        apply_update: bool,
        target_dir: Path | None = None,
    ):
        super().__init__()
        self._installed_version = installed_version
        self._allow_prerelease = allow_prerelease
        self._apply_update = apply_update
        self._target_dir = target_dir

    def run(self) -> None:
        result = check_and_update_geo(
            self._installed_version,
            allow_prerelease=self._allow_prerelease,
            apply_update=self._apply_update,
            target_dir=self._target_dir,
            on_progress=lambda p: self.progress.emit(p),
        )
        self.done.emit(result)
