"""
Plugin for recovering web filter ("block page") artifacts from browser
history and Cache data.

Managed devices - school-issued laptops in particular, but also
home/parental-control setups - intercept disallowed browsing and redirect the
user to a vendor "block page". These hits remain in the browser's history and
cache even though the blocked site itself was never loaded, and the block
page URL frequently embeds the blocked target URL, the blocking category and
sometimes the user/group identity, making them strong corroboration of what
was attempted and when. Vendors currently recognised:

* GoGuardian (blocked.goguardian.com)
* Linewize (blocked.<region>.linewize.net)
* Securly (securly.com/blocked, useast2-www.securly.com/blocked)
* BlockSi (block.si/block, and its Chrome extension pages)
* Lightspeed Filter (lightspeedsystems.com, and its Chrome extension pages)
* Microsoft Family Safety (sdx.microsoft.com - home focused)
* eero Secure (blocked.eero.com - home focused)
* Circle (filter.meetcircle.com - home focused)

Heuristics: a URL is treated as a block page where the host is a known
vendor's, where the host begins with "blocked."/"filter.", or where the path
contains "/blocked" or is "/block". Chrome extension URLs are matched on
known vendor tokens within the URL. Treat generic heuristic matches
(vendor "Unknown") with care.

A second artifact recovers queries to the Internet Archive's Wayback Machine
timemap/CDX APIs found in history and cache. On seized devices these reveal
that someone queried the archive - and, where the archived target was a block
page host, they preserve the block page URL schemas (which the archive and
web searches have indexed) even where local records were wiped.
"""
import datetime
import re
import urllib.parse

from mister_skinnylegs.util.artifact_utils import ArtifactResult, ArtifactSpec, LogFunction, ReportPresentation, ArtifactStorage
from mister_skinnylegs.util.profile_folder_protocols import BrowserProfileProtocol


# Vendor tokens mapped to friendly names (matched case-insensitively anywhere
# in the URL, which also covers chrome-extension:// pages for the vendors
# whose block pages are served from extension contexts).
VENDOR_TOKENS = (
    ("goguardian.com", "GoGuardian"),
    ("goguardian", "GoGuardian"),
    ("linewize.net", "Linewize"),
    ("linewize", "Linewize"),
    ("securly.com", "Securly"),
    ("securly", "Securly"),
    ("block.si", "BlockSi"),
    ("blocksi", "BlockSi"),
    ("lightspeed", "Lightspeed Filter"),
    ("sdx.microsoft.com", "Microsoft Family Safety"),
    ("eero.com", "eero"),
    ("meetcircle.com", "Circle"),
)

# Block page URL indicators applied to the parsed host/path
BLOCK_HOST_SUFFIXES = tuple(token for token, _ in VENDOR_TOKENS)
BLOCK_HOST_PREFIXES = ("blocked.", "filter.")
BLOCK_PATH_SUBSTRING = "/blocked"
BLOCK_PATHS = ("/block",)

# Chrome extension contexts (e.g. newer BlockSi and Lightspeed block pages)
CHROME_EXTENSION_SCHEME = "chrome-extension://"
EXTENSION_VENDOR_TOKENS = ("blocksi", "lightspeed", "goguardian", "securly", "linewize")

# Wayback Machine APIs (timemap and CDX) - queries against these reveal what
# was being looked for in the archive.
WAYBACK_API_URL_PATTERN = re.compile(r"https?://web\.archive\.org/(?:web/timemap/|cdx/search/cdx)")

EPOCH = datetime.datetime(1970, 1, 1)


def _vendor_for(url: str):
    """
    Returns the friendly vendor name for a block page URL, or None where the
    match was purely heuristic (e.g. an unknown host with a /blocked path).
    """
    lowered = url.lower()
    for token, vendor in VENDOR_TOKENS:
        if token in lowered:
            return vendor
    return None


def _is_block_page(url: str):
    """
    Heuristically determines whether a URL is a web filter block page.
    Returns the matched vendor name (or None for heuristic-only matches),
    or False where the URL does not look like a block page.
    """
    lowered = url.lower()

    if lowered.startswith(CHROME_EXTENSION_SCHEME):
        if any(token in lowered for token in EXTENSION_VENDOR_TOKENS):
            return _vendor_for(lowered) or "Unknown (extension)"
        return False

    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    path = parts.path or ""

    if host.endswith(BLOCK_HOST_SUFFIXES):
        return _vendor_for(host)
    if host.startswith(BLOCK_HOST_PREFIXES):
        return _vendor_for(url)
    if BLOCK_PATH_SUBSTRING in path or path in BLOCK_PATHS:
        return _vendor_for(url)
    return False


def _query_params_lower(url: str) -> dict:
    """
    Returns the URL's query parameters as a {lowercase name: [values]} dict,
    preserving the original values.
    """
    try:
        return {name.lower(): values for name, values in
                urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
    except ValueError:
        return {}


def _first_param(params: dict, names) -> str:
    for name in names:
        values = params.get(name)
        if values:
            return values[0]
    return None


def _decode_unix_ms_param(value, min_micros: int = int(1e12), max_micros: int = int(4.1e12)):
    """
    Decodes a millisecond Unix timestamp string (e.g. the cache-buster "_"/"*"
    parameter on Wayback API requests) to a UTC datetime, returning None for
    values outside a sane range (2001-2100).
    """
    if value is None or not str(value).isdigit():
        return None
    ms = int(value)
    if not min_micros <= ms <= max_micros:
        return None
    return EPOCH + datetime.timedelta(milliseconds=ms)


def get_block_pages(profile: BrowserProfileProtocol, log_func: LogFunction,
                    storage: ArtifactStorage) -> ArtifactResult:
    """
    Recovers web filter block page URLs from history and cache keys, with the
    vendor, and (where the block page URL embeds them) the blocked target URL,
    blocking category and user identity.
    """
    # parameters commonly carrying the blocked target, the category/reason and
    # the user identity (case-insensitive)
    TARGET_PARAM_NAMES = ("url", "u", "web_addr", "site", "original_url", "blocked_url", "target", "ref_url")
    CATEGORY_PARAM_NAMES = ("cat", "category", "reason", "block_reason", "policy", "policyname")
    USER_PARAM_NAMES = ("user", "username", "email", "uid", "student", "student_email", "account")
    PAGE_PARAM_NAMES = ("page", "title", "name")

    results = []

    def add_result(url: str, source: str, timestamp, location):
        vendor = _is_block_page(url)
        if vendor is False:
            return
        params = _query_params_lower(url)
        target = _first_param(params, TARGET_PARAM_NAMES)
        # a target may itself be URL-encoded twice (filter -> block page)
        if target and target.lower().startswith(("http%3a", "https%3a")):
            target = urllib.parse.unquote(target)
        other = ", ".join(f"{name}={value}" for name, values in sorted(params.items())
                          for value in values
                          if name not in TARGET_PARAM_NAMES + CATEGORY_PARAM_NAMES
                          + USER_PARAM_NAMES + PAGE_PARAM_NAMES)
        results.append({
            "vendor": vendor,
            "source": source,
            "timestamp": timestamp,
            "blocked url param": target,
            "category/reason param": _first_param(params, CATEGORY_PARAM_NAMES),
            "user param": _first_param(params, USER_PARAM_NAMES),
            "page param": _first_param(params, PAGE_PARAM_NAMES),
            "other parameters": other or None,
            "original url": url,
            "location": location,
        })

    for history_rec in profile.iterate_history_records(url=_block_page_url_filter):
        add_result(history_rec.url, "History", history_rec.visit_time,
                   f"{history_rec.record_location}")

    for cache_rec in profile.iterate_cache(url=_block_page_url_filter, omit_cached_data=True):
        add_result(cache_rec.key.url, "Cache URLs",
                   cache_rec.metadata.request_time if cache_rec.metadata is not None else None,
                   f"{cache_rec.metadata_location}")

    results.sort(key=lambda r: (r["timestamp"] or datetime.datetime(1601, 1, 1)))
    return ArtifactResult(results)


def _block_page_url_filter(url: str) -> bool:
    """
    KeySearch-style predicate for profile.iterate_history_records/iterate_cache.
    """
    return _is_block_page(url) is not False


def get_wayback_lookups(profile: BrowserProfileProtocol, log_func: LogFunction,
                        storage: ArtifactStorage) -> ArtifactResult:
    """
    Recovers Internet Archive Wayback Machine API queries (timemap/CDX) from
    history and cache. The archived target URL is decoded from the request and
    classified, so that (for example) timemap queries against known block page
    hosts are visible even where the local block page records were removed.
    """
    results = []

    def add_result(url: str, source: str, timestamp, location):
        params = _query_params_lower(url)
        target = _first_param(params, ("url",))
        if not target:
            return  # not a usable archive query
        target_is_block_page = _is_block_page(target)
        match_type = _first_param(params, ("matchtype",))
        lookup_timestamp = _decode_unix_ms_param(_first_param(params, ("*", "_")))
        results.append({
            "source": source,
            "timestamp": timestamp,
            "lookup timestamp (from row param)": lookup_timestamp,
            "archived target url": target,
            "target is block page": target_is_block_page if target_is_block_page is not False else False,
            "target vendor": target_is_block_page if target_is_block_page else None,
            "match type": match_type,
            "output format": _first_param(params, ("output",)),
            "limit": _first_param(params, ("limit",)),
            "original url": url,
            "location": location,
        })

    for history_rec in profile.iterate_history_records(url=WAYBACK_API_URL_PATTERN):
        add_result(history_rec.url, "History", history_rec.visit_time,
                   f"{history_rec.record_location}")

    for cache_rec in profile.iterate_cache(url=WAYBACK_API_URL_PATTERN, omit_cached_data=True):
        add_result(cache_rec.key.url, "Cache URLs",
                   cache_rec.metadata.request_time if cache_rec.metadata is not None else None,
                   f"{cache_rec.metadata_location}")

    results.sort(key=lambda r: (r["timestamp"] or datetime.datetime(1601, 1, 1)))
    return ArtifactResult(results)


__artifacts__ = (
    ArtifactSpec(
        "Web Filters",
        "Web Filter Block Pages",
        "Recovers web filter block page URLs (GoGuardian, Linewize, Securly, BlockSi, "
        "Lightspeed, Microsoft Family Safety, eero, Circle) from history and cache, "
        "including embedded blocked target/category/user parameters",
        "0.1",
        get_block_pages,
        ReportPresentation.table,
        timestamp_field_names=("timestamp",)
    ),
    ArtifactSpec(
        "Web Filters",
        "Wayback Machine Lookups",
        "Recovers Internet Archive timemap/CDX API queries from history and cache, with "
        "the decoded archived target URL classified against known block page hosts",
        "0.1",
        get_wayback_lookups,
        ReportPresentation.table,
        timestamp_field_names=("timestamp", "lookup timestamp (from row param)")
    ),
)
