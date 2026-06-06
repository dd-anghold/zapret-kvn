"""Sing-box-extended updater: downloads from shtorm-7/sing-box-extended."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request

from PyQt6.QtCore import QThread, pyqtSignal

from .constants import BASE_DIR, SINGBOX_EXTENDED_GITHUB_RELEASES_API, SINGBOX_PATH_DEFAULT
from .http_utils import urlopen


USER_AGENT = "ZapretKVN/0.4"

_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?")


def _extract_version(text: str) -> str:
    value = text.strip().lstrip("v")
    match = _SEMVER_RE.search(value)
    if not match:
        return value
    major, minor, patch, suffix = match.groups()
    return f"{major}.{minor}.{patch}-{suffix}" if suffix else f"{major}.{minor}.{patch}"


def _parse_semver(version: str) -> tuple[int, int, int, list[str]] | None:
    match = _SEMVER_RE.search(version.strip().lstrip("v"))
    if not match:
        return None
    major, minor, patch, suffix = match.groups()
    prerelease = suffix.split(".") if suffix else []
    return int(major), int(minor), int(patch), prerelease


def _is_newer(latest: str, current: str) -> bool:
    lp = _parse_semver(latest)
    cp = _parse_semver(current)
    if lp is None or cp is None:
        return _extract_version(latest) != _extract_version(current)
    if lp[:3] != cp[:3]:
        return lp[:3] > cp[:3]
    # stable > prerelease: empty prerelease means stable
    if not lp[3] and cp[3]:
        return True
    if lp[3] and not cp[3]:
        return False
    return lp[3] > cp[3]


def _request_json(url: str) -> object:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def _pick_release(releases: list[dict], allow_prerelease: bool) -> dict | None:
    for release in releases:
        if release.get("draft"):
            continue
        if bool(release.get("prerelease")) and not allow_prerelease:
            continue
        return release
    return None


def _find_windows_asset(release: dict) -> dict | None:
    """Find the windows amd64 zip asset."""
    candidates = []
    for asset in release.get("assets", []):
        name = str(asset.get("name") or "").lower()
        if not name.endswith(".zip"):
            continue
        if ("windows" in name or "win" in name) and ("amd64" in name or "64" in name or "x86_64" in name):
            candidates.append(asset)
    if candidates:
        return candidates[0]
    # Fallback: any zip with amd64/64
    for asset in release.get("assets", []):
        name = str(asset.get("name") or "").lower()
        if name.endswith(".zip") and ("amd64" in name or "x86_64" in name):
            return asset
    return None


def _extract_digest(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1].strip()
    match = re.search(r"([a-f0-9]{64})", text)
    return match.group(1) if match else ""


def _fetch_dgst_hash(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=12) as response:
        body = response.read().decode("utf-8", errors="replace")
    return _extract_digest(body)


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


def _find_file(root: Path, name: str) -> Path | None:
    for path in root.rglob(name):
        if path.is_file():
            return path
    return None


@dataclass(slots=True)
class SingboxExtendedRelease:
    version: str
    url: str
    digest_sha256: str = ""


@dataclass(slots=True)
class SingboxExtendedUpdateResult:
    status: str  # up_to_date | available | updated | error
    message: str
    current_version: str
    latest_version: str
    updated: bool = False


def resolve_singbox_extended_release(allow_prerelease: bool = False) -> SingboxExtendedRelease | None:
    payload = _request_json(SINGBOX_EXTENDED_GITHUB_RELEASES_API)
    if not isinstance(payload, list):
        return None
    release = _pick_release([r for r in payload if isinstance(r, dict)], allow_prerelease)
    if not release:
        return None

    asset = _find_windows_asset(release)
    if not asset:
        return None

    digest = _extract_digest(str(asset.get("digest") or ""))
    if not digest:
        asset_name = str(asset.get("name") or "")
        for suffix in (".sha256", ".dgst", ".sha256sum"):
            expected = f"{asset_name}{suffix}".lower()
            sidecar = next(
                (a for a in release.get("assets", []) if str(a.get("name") or "").lower() == expected),
                None,
            )
            if sidecar:
                digest = _fetch_dgst_hash(str(sidecar.get("browser_download_url") or ""))
                break

    version = str(release.get("tag_name") or release.get("name") or "")
    return SingboxExtendedRelease(
        version=_extract_version(version),
        url=str(asset.get("browser_download_url") or ""),
        digest_sha256=digest,
    )


def check_and_update_singbox_extended(
    singbox_path: str,
    installed_version: str,
    allow_prerelease: bool = False,
    apply_update: bool = False,
    on_progress=None,
) -> SingboxExtendedUpdateResult:
    from .path_utils import resolve_configured_path

    exe = resolve_configured_path(
        singbox_path,
        default_path=SINGBOX_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    if exe is None:
        exe = SINGBOX_PATH_DEFAULT

    # Get current installed version from binary or stored version
    current_version = installed_version
    if exe.exists() and not current_version:
        try:
            from .engines.singbox.manager import get_singbox_version
            raw = get_singbox_version(singbox_path) or ""
            current_version = _extract_version(raw) if raw else ""
        except Exception:
            pass

    try:
        release = resolve_singbox_extended_release(allow_prerelease)
    except Exception as exc:
        return SingboxExtendedUpdateResult(
            status="error",
            message=f"Ошибка получения информации о релизе: {exc}",
            current_version=current_version,
            latest_version="",
        )

    if not release or not release.url:
        return SingboxExtendedUpdateResult(
            status="error",
            message="Релиз sing-box-extended не найден",
            current_version=current_version,
            latest_version="",
        )

    latest_version = release.version
    if current_version and not _is_newer(latest_version, current_version):
        return SingboxExtendedUpdateResult(
            status="up_to_date",
            message=f"sing-box-extended актуален ({current_version})",
            current_version=current_version,
            latest_version=latest_version,
        )

    if not apply_update:
        return SingboxExtendedUpdateResult(
            status="available",
            message=f"Доступно обновление sing-box-extended: {latest_version}",
            current_version=current_version,
            latest_version=latest_version,
        )

    with tempfile.TemporaryDirectory(prefix="singbox_ext_update_") as tmp_str:
        tmp = Path(tmp_str)
        archive_path = tmp / "singbox-extended.zip"

        try:
            _download_file(release.url, archive_path, on_progress=lambda d, t: on_progress and on_progress(int(d * 100 / t)))
        except Exception as exc:
            return SingboxExtendedUpdateResult(
                status="error",
                message=f"Ошибка загрузки: {exc}",
                current_version=current_version,
                latest_version=latest_version,
            )

        if release.digest_sha256:
            real_hash = _sha256_file(archive_path)
            if real_hash.lower() != release.digest_sha256.lower():
                return SingboxExtendedUpdateResult(
                    status="error",
                    message="Контрольная сумма архива не совпадает",
                    current_version=current_version,
                    latest_version=latest_version,
                )

        extract_dir = tmp / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(extract_dir)

        # Find sing-box.exe or sing-box-extended.exe
        new_exe = _find_file(extract_dir, "sing-box-extended.exe") or _find_file(extract_dir, "sing-box.exe")
        if not new_exe:
            return SingboxExtendedUpdateResult(
                status="error",
                message="sing-box.exe не найден в архиве",
                current_version=current_version,
                latest_version=latest_version,
            )

        target = exe
        target.parent.mkdir(parents=True, exist_ok=True)

        if target.exists():
            bak = target.with_suffix(".exe.bak")
            try:
                shutil.copy2(target, bak)
            except Exception:
                pass

        try:
            shutil.copy2(new_exe, target)
        except Exception as exc:
            return SingboxExtendedUpdateResult(
                status="error",
                message=f"Ошибка установки: {exc}",
                current_version=current_version,
                latest_version=latest_version,
            )

    if on_progress:
        on_progress(100)

    return SingboxExtendedUpdateResult(
        status="updated",
        message=f"sing-box-extended обновлён до {latest_version}",
        current_version=current_version,
        latest_version=latest_version,
        updated=True,
    )


class SingboxExtendedUpdateWorker(QThread):
    done = pyqtSignal(object)   # SingboxExtendedUpdateResult
    progress = pyqtSignal(int)  # 0-100

    def __init__(
        self,
        singbox_path: str,
        installed_version: str,
        allow_prerelease: bool,
        apply_update: bool,
    ):
        super().__init__()
        self._singbox_path = singbox_path
        self._installed_version = installed_version
        self._allow_prerelease = allow_prerelease
        self._apply_update = apply_update

    def run(self) -> None:
        result = check_and_update_singbox_extended(
            self._singbox_path,
            self._installed_version,
            allow_prerelease=self._allow_prerelease,
            apply_update=self._apply_update,
            on_progress=lambda p: self.progress.emit(p),
        )
        self.done.emit(result)
