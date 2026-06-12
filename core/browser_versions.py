# browser_versions.py - browser version provider module
# Purpose: Fetch, cache, and normalize live upstream browser version tracks.

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import logging
import re
import threading
from typing import Any
import urllib.error
import urllib.request


logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL = timedelta(hours=24)
ERROR_CACHE_TTL = timedelta(minutes=15)
HTTP_TIMEOUT_SECONDS = 8
BROWSER_VERSION_USER_AGENT = "SystemShield browser-version-provider"

CHROME_CHANNELS_URL = "https://chromestatus.com/api/v0/channels"
FIREFOX_VERSIONS_URL = "https://product-details.mozilla.org/1.0/firefox_versions.json"
EDGE_PRODUCTS_URL = "https://edgeupdates.microsoft.com/api/products"
BRAVE_RELEASE_URL = "https://api.github.com/repos/brave/brave-browser/releases/latest"


@dataclass(frozen=True)
class BrowserVersionState:
    browser: str
    engine: str
    channel: str
    major: int
    version: str
    upstream: str
    source_url: str
    source_type: str
    fetched_at: str


@dataclass(frozen=True)
class BrowserVersionSnapshot:
    states: dict[str, BrowserVersionState]
    fetched_at: datetime
    expires_at: datetime
    warnings: tuple[str, ...] = ()


_CACHE: BrowserVersionSnapshot | None = None
_CACHE_LOCK = threading.Lock()
_ASYNC_FETCH_LOCK: asyncio.Lock | None = None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _now_utc().isoformat()


def _cache_valid(ttl: timedelta) -> bool:
    if _CACHE is None:
        return False
    expires_at = _CACHE.expires_at or (_CACHE.fetched_at + ttl)
    return _now_utc() < expires_at


def _state(
    browser: str,
    engine: str,
    major: int,
    version: str,
    upstream: str,
    source_url: str,
    source_type: str,
    fetched_at: str,
    channel: str = "stable",
) -> BrowserVersionState:
    return BrowserVersionState(
        browser=browser,
        engine=engine,
        channel=channel,
        major=major,
        version=version,
        upstream=upstream,
        source_url=source_url,
        source_type=source_type,
        fetched_at=fetched_at,
    )


def _major_from_version(value: Any) -> int | None:
    match = re.search(r"\d+", str(value or ""))
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def _strip_xssi_prefix(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith(")]}'"):
        newline_index = stripped.find("\n")
        if newline_index >= 0:
            return stripped[newline_index + 1 :].strip()
        brace_index = stripped.find("{")
        bracket_index = stripped.find("[")
        indexes = [idx for idx in (brace_index, bracket_index) if idx >= 0]
        if indexes:
            return stripped[min(indexes) :].strip()
    return text


def _urllib_fetch_text(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/plain, */*",
            "User-Agent": BROWSER_VERSION_USER_AGENT,
        },
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", errors="replace")


async def _fetch_text(url: str) -> str:
    try:
        import httpx

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True) as client:
            response = await client.get(
                url,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "User-Agent": BROWSER_VERSION_USER_AGENT,
                },
            )
            response.raise_for_status()
            return response.text
    except ImportError:
        pass

    try:
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "User-Agent": BROWSER_VERSION_USER_AGENT,
                },
            ) as response:
                response.raise_for_status()
                return await response.text()
    except ImportError:
        pass

    return await asyncio.to_thread(_urllib_fetch_text, url)


async def _fetch_json(url: str) -> Any:
    text = await _fetch_text(url)
    return json.loads(_strip_xssi_prefix(text))


def _chrome_state_from_payload(payload: Any, fetched_at: str) -> BrowserVersionState | None:
    stable = payload.get("stable") if isinstance(payload, dict) else None
    if not isinstance(stable, dict):
        return None

    major = _major_from_version(stable.get("mstone") or stable.get("version"))
    if major is None:
        return None

    version = str(stable.get("version") or stable.get("mstone") or major)
    return _state(
        "Google Chrome",
        "Chromium",
        major,
        version,
        "Chromium",
        CHROME_CHANNELS_URL,
        "direct",
        fetched_at,
    )


def _firefox_state_from_payload(
    payload: Any,
    fetched_at: str,
    browser: str = "Mozilla Firefox",
    channel: str = "stable",
    version_keys: tuple[str, ...] = ("LATEST_FIREFOX_VERSION", "FIREFOX_NIGHTLY"),
) -> BrowserVersionState | None:
    if not isinstance(payload, dict):
        return None

    version = next((payload.get(key) for key in version_keys if payload.get(key)), None)
    major = _major_from_version(version)
    if major is None:
        return None

    return _state(
        browser,
        "Gecko",
        major,
        str(version),
        "Mozilla Firefox",
        FIREFOX_VERSIONS_URL,
        "direct",
        fetched_at,
        channel,
    )


def _edge_state_from_payload(payload: Any, fetched_at: str) -> BrowserVersionState | None:
    if not isinstance(payload, list):
        return None

    stable_versions = []
    for product in payload:
        if not isinstance(product, dict):
            continue
        if str(product.get("Product") or "").lower() != "stable":
            continue
        for release in product.get("Releases") or []:
            if not isinstance(release, dict):
                continue
            version = release.get("ProductVersion")
            major = _major_from_version(version)
            if major is not None:
                stable_versions.append((major, str(version)))

    if not stable_versions:
        return None

    major, version = max(stable_versions, key=lambda item: item[0])
    return _state(
        "Microsoft Edge",
        "Chromium",
        major,
        version,
        "Microsoft Edge",
        EDGE_PRODUCTS_URL,
        "direct",
        fetched_at,
    )


def _brave_chromium_major_from_payload(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    text_parts = [
        str(payload.get("tag_name") or ""),
        str(payload.get("name") or ""),
        str(payload.get("body") or ""),
    ]
    text = "\n".join(text_parts)
    match = re.search(r"chromium[^0-9]*(\d+)", text, flags=re.IGNORECASE)
    return int(match.group(1)) if match else None


async def _fetch_live_states() -> tuple[dict[str, BrowserVersionState], tuple[str, ...]]:
    fetched_at = _iso_now()
    warnings = []
    states: dict[str, BrowserVersionState] = {}

    async def guarded(label: str, url: str):
        try:
            return await _fetch_json(url)
        except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            warnings.append(f"{label}: {exc}")
            return None
        except Exception as exc:
            warnings.append(f"{label}: {exc}")
            return None

    chrome_payload, firefox_payload, edge_payload, brave_payload = await asyncio.gather(
        guarded("Chrome channels", CHROME_CHANNELS_URL),
        guarded("Firefox versions", FIREFOX_VERSIONS_URL),
        guarded("Edge products", EDGE_PRODUCTS_URL),
        guarded("Brave release", BRAVE_RELEASE_URL),
    )

    chrome_state = _chrome_state_from_payload(chrome_payload, fetched_at)
    if chrome_state:
        states[chrome_state.browser] = chrome_state
        states["Chromium"] = _state(
            "Chromium",
            "Chromium",
            chrome_state.major,
            chrome_state.version,
            "Chromium",
            chrome_state.source_url,
            "derived_upstream",
            fetched_at,
        )

    firefox_state = _firefox_state_from_payload(firefox_payload, fetched_at)
    if firefox_state:
        states[firefox_state.browser] = firefox_state

    firefox_dev_state = _firefox_state_from_payload(
        firefox_payload,
        fetched_at,
        browser="Firefox Developer Edition",
        channel="developer",
        version_keys=(
            "FIREFOX_DEVEDITION",
            "LATEST_FIREFOX_DEVEL_VERSION",
            "LATEST_FIREFOX_RELEASED_DEVEL_VERSION",
        ),
    )
    if firefox_dev_state:
        states[firefox_dev_state.browser] = firefox_dev_state

    edge_state = _edge_state_from_payload(edge_payload, fetched_at)
    if edge_state:
        states[edge_state.browser] = edge_state

    brave_chromium_major = _brave_chromium_major_from_payload(brave_payload)
    chromium_source = states.get("Google Chrome")
    if brave_chromium_major is not None:
        states["Brave"] = _state(
            "Brave",
            "Chromium",
            brave_chromium_major,
            str(brave_chromium_major),
            "Chromium",
            BRAVE_RELEASE_URL,
            "direct_engine",
            fetched_at,
        )
    elif chromium_source:
        states["Brave"] = _derive_chromium_state("Brave", chromium_source, fetched_at)

    if chromium_source:
        for browser in ("Opera", "Opera GX", "Vivaldi", "Arc"):
            states[browser] = _derive_chromium_state(browser, chromium_source, fetched_at)

    return states, tuple(warnings)


def _derive_chromium_state(
    browser: str,
    chromium_source: BrowserVersionState,
    fetched_at: str,
) -> BrowserVersionState:
    return _state(
        browser,
        "Chromium",
        chromium_source.major,
        chromium_source.version,
        "Chromium",
        chromium_source.source_url,
        "derived_upstream",
        fetched_at,
    )


async def get_browser_version_state_map_async(
    force: bool = False,
    ttl: timedelta = DEFAULT_CACHE_TTL,
) -> dict[str, BrowserVersionState]:
    global _CACHE, _ASYNC_FETCH_LOCK

    with _CACHE_LOCK:
        if not force and _cache_valid(ttl):
            return dict(_CACHE.states) if _CACHE else {}

    if _ASYNC_FETCH_LOCK is None:
        _ASYNC_FETCH_LOCK = asyncio.Lock()

    async with _ASYNC_FETCH_LOCK:
        with _CACHE_LOCK:
            if not force and _cache_valid(ttl):
                return dict(_CACHE.states) if _CACHE else {}

        with _CACHE_LOCK:
            stale_states = dict(_CACHE.states) if _CACHE else {}

        states, warnings = await _fetch_live_states()
        if not states:
            if stale_states:
                logger.warning("Browser version live fetch failed; using stale in-memory cache.")
                states = stale_states
            else:
                logger.warning(
                    "Browser version live fetch failed and no cache is available; browser statuses will default to check."
                )
        elif warnings:
            stale_fill = {
                name: state
                for name, state in stale_states.items()
                if name not in states
            }
            if stale_fill:
                states.update(stale_fill)
                warnings = warnings + (
                    "Using stale cached browser tracks for: " + ", ".join(sorted(stale_fill)),
                )
            logger.warning("Browser version provider recovered with partial live data: %s", "; ".join(warnings))

        fetched_at = _now_utc()
        snapshot = BrowserVersionSnapshot(
            states=states,
            fetched_at=fetched_at,
            expires_at=fetched_at + (ttl if states else ERROR_CACHE_TTL),
            warnings=warnings,
        )
        with _CACHE_LOCK:
            _CACHE = snapshot
        return dict(states)


def _run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result = {}
    error = {}

    def runner():
        try:
            result["value"] = asyncio.run(coro)
        except Exception as exc:
            error["exception"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error["exception"]
    return result.get("value")


def get_browser_version_state_map(force: bool = False) -> dict[str, dict[str, Any]]:
    states = _run_async(get_browser_version_state_map_async(force=force))
    return {name: asdict(state) for name, state in states.items()}


def get_latest_browser_versions(force: bool = False) -> dict[str, int]:
    states = _run_async(get_browser_version_state_map_async(force=force))
    return {name: state.major for name, state in states.items() if isinstance(state.major, int)}


def get_browser_version_state(browser_name: str) -> dict[str, Any] | None:
    return get_browser_version_state_map().get(browser_name)


def is_derived_upstream_state(browser_name: str) -> bool:
    state = get_browser_version_state(browser_name)
    return bool(state and state.get("source_type") == "derived_upstream")
