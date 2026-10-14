"""Web research tools for URL fetching and web search."""

import hashlib
import json
import logging
import os
import time
from urllib.parse import urlparse

import requests

from constants import VULN_CACHE_PATH

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 4 * 3600  # 4 hours


def _is_url_blocked(url: str, blocked_domains: tuple[str, ...]) -> bool:
    """Check if a URL matches any domain in blocked_domains.

    Matches exact domain and any subdomains (e.g. github.com matches a.a.github.com).
    """
    if not blocked_domains or not url:
        return False
    try:
        netloc = urlparse(url).netloc.lower()
        if not netloc:
            netloc = urlparse("http://" + url).netloc.lower()
        hostname = netloc.split(":")[0].strip()
        if not hostname:
            return False
        for domain in blocked_domains:
            domain = domain.lower().strip()
            if hostname == domain or hostname.endswith("." + domain):
                return True
        return False
    except Exception:
        return False


def _filter_search_results(
    results: list[dict], blocked_domains: tuple[str, ...]
) -> list[dict]:
    """Filter out search results whose URLs match any domain in blocked_domains."""
    if not blocked_domains or not results:
        return results
    filtered = []
    for r in results:
        url = r.get("url", "")
        if url and _is_url_blocked(url, blocked_domains):
            continue
        filtered.append(r)
    return filtered


def _cache_key(prefix: str, **kwargs) -> str:
    raw = prefix + json.dumps(kwargs, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _get_cached(key: str):
    path = os.path.join(VULN_CACHE_PATH, f"{key}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if time.time() - data.get("_cached_at", 0) > CACHE_TTL_SECONDS:
            return None
        return data.get("result")
    except (json.JSONDecodeError, OSError):
        return None


def _set_cached(key: str, result):
    os.makedirs(VULN_CACHE_PATH, exist_ok=True)
    path = os.path.join(VULN_CACHE_PATH, f"{key}.json")
    with open(path, "w") as f:
        json.dump({"_cached_at": time.time(), "result": result}, f)


# --- Web search helpers ---
_last_web_search_call = 0.0
WEB_SEARCH_CACHE_TTL = 3600  # 1 hour


def _web_search(query: str, max_results: int = 10) -> list[dict]:
    """Dispatch web search to configured provider."""
    from constants import WEB_SEARCH_PROVIDER

    provider = WEB_SEARCH_PROVIDER.lower()
    if provider == "exa":
        return _web_search_exa(query, max_results)
    elif provider == "tavily":
        return _web_search_tavily(query, max_results)
    return _web_search_ddg(query, max_results)


def _web_search_ddg(query: str, max_results: int = 10) -> list[dict]:
    """Search DuckDuckGo HTML endpoint (no API key required)."""
    import re
    from urllib.parse import unquote

    global _last_web_search_call
    elapsed = time.time() - _last_web_search_call
    if elapsed < 2.0:
        time.sleep(2.0 - elapsed)
    _last_web_search_call = time.time()

    try:
        resp = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=15,
        )
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"DuckDuckGo search error: {e}")
        return [{"error": str(e)}]

    results = []
    try:
        from lxml import html as lxml_html

        doc = lxml_html.fromstring(resp.content)
        for link_el in doc.cssselect(".result__a"):
            href = link_el.get("href", "")
            title = link_el.text_content().strip()
            # Extract snippet from sibling
            snippet_el = link_el.getparent().getnext()
            snippet = (
                snippet_el.text_content().strip() if snippet_el is not None else ""
            )
            # DDG wraps URLs in redirects — extract actual URL
            actual_url = href
            if "uddg=" in href:
                match = re.search(r"uddg=([^&]+)", href)
                if match:
                    actual_url = unquote(match.group(1))
            if actual_url and not actual_url.startswith("/"):
                results.append(
                    {"title": title, "url": actual_url, "snippet": snippet[:300]}
                )
            if len(results) >= max_results:
                break
    except ImportError:
        # Fallback to regex parsing
        link_pattern = re.compile(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.DOTALL
        )
        snippet_pattern = re.compile(
            r'class="result__snippet"[^>]*>(.*?)</(?:a|td|div)', re.DOTALL
        )
        links = link_pattern.findall(resp.text)
        snippets = snippet_pattern.findall(resp.text)
        for i, (href, title_html) in enumerate(links):
            if i >= max_results:
                break
            title = re.sub(r"<[^>]+>", "", title_html).strip()
            snippet = (
                re.sub(r"<[^>]+>", "", snippets[i]).strip() if i < len(snippets) else ""
            )
            actual_url = href
            if "uddg=" in href:
                match = re.search(r"uddg=([^&]+)", href)
                if match:
                    actual_url = unquote(match.group(1))
            if actual_url and not actual_url.startswith("/"):
                results.append(
                    {"title": title, "url": actual_url, "snippet": snippet[:300]}
                )

    return results


def _web_search_exa(query: str, max_results: int = 10) -> list[dict]:
    """Search via Exa API (requires EXA_API_KEY env var)."""
    api_key = os.environ.get("EXA_API_KEY", "")
    if not api_key:
        return [{"error": "EXA_API_KEY not set"}]
    try:
        resp = requests.post(
            "https://api.exa.ai/search",
            json={"query": query, "numResults": max_results, "useAutoprompt": True},
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        return [
            {
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "snippet": r.get("text", "")[:300],
            }
            for r in data.get("results", [])[:max_results]
        ]
    except Exception as e:
        logger.error(f"Exa search error: {e}")
        return [{"error": str(e)}]


def _web_search_tavily(query: str, max_results: int = 10) -> list[dict]:
    """Search via Tavily API (requires TAVILY_API_KEY in secret_keys.py)."""
    from constants import TAVILY_API_KEY

    api_key = TAVILY_API_KEY
    if not api_key:
        return [{"error": "TAVILY_API_KEY not set"}]
    try:
        resp = requests.post(
            "https://api.tavily.com/search",
            json={"query": query, "max_results": max_results, "api_key": api_key},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        return [
            {
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "snippet": r.get("content", "")[:300],
            }
            for r in data.get("results", [])[:max_results]
        ]
    except Exception as e:
        logger.error(f"Tavily search error: {e}")
        return [{"error": str(e)}]


_CODE_EXTENSIONS = {
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".py",
    ".rs",
    ".go",
    ".java",
    ".js",
    ".ts",
}


def _github_blob_to_raw(url: str) -> str:
    """Convert GitHub blob URL to raw.githubusercontent.com URL."""
    import re

    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/blob/(.+)", url)
    if m:
        owner, repo, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{path}"
    return url


def _github_tree_to_api(url: str) -> str | None:
    """Convert GitHub tree/repo URLs to the Contents API endpoint.

    Returns None for non-matching URLs (blob URLs, non-GitHub, etc.).

    Examples:
        github.com/owner/repo/tree/branch/path → api.github.com/repos/owner/repo/contents/path?ref=branch
        github.com/owner/repo                  → api.github.com/repos/owner/repo/contents/
    """
    import re

    # Match tree URLs: github.com/owner/repo/tree/branch/path
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/?(.*)", url)
    if m:
        owner, repo, branch, path = m.groups()
        path = path.rstrip("/")
        api = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        if branch:
            api += f"?ref={branch}"
        return api

    # Match bare repo URLs: github.com/owner/repo (no /blob, /tree, /issues, etc.)
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/?$", url)
    if m:
        owner, repo = m.groups()
        return f"https://api.github.com/repos/{owner}/{repo}/contents/"

    return None


def _format_github_directory(entries: list[dict], repo_url: str = "") -> str:
    """Format GitHub Contents API JSON into a readable directory listing."""
    dirs = []
    files = []

    for entry in entries:
        name = entry.get("name", "")
        entry_type = entry.get("type", "")
        if entry_type == "dir":
            dirs.append(name)
        elif entry_type == "file":
            size = entry.get("size", 0)
            download_url = entry.get("download_url", "")
            files.append((name, size, download_url))

    lines = []
    if repo_url:
        lines.append(f"Directory listing for: {repo_url}")
    lines.append("")

    if dirs:
        lines.append("Directories:")
        for d in sorted(dirs):
            lines.append(f"  {d}/")
        lines.append("")

    if files:
        lines.append("Files:")
        for name, size, dl_url in sorted(files):
            line = f"  {name} ({size} bytes)"
            if dl_url:
                line += f"  -> {dl_url}"
            lines.append(line)

    return "\n".join(lines)


def _adaptive_max_chars(url: str, default: int) -> int:
    """Return higher max_chars for code file URLs."""
    from posixpath import splitext

    _, ext = splitext(url.rstrip("/").split("?")[0])
    if ext.lower() in _CODE_EXTENSIONS:
        return max(default, 20000)
    return default


def _fetch_url_text(url: str, max_chars: int = 5000, enable_github: bool = True) -> str:
    """Fetch a URL and extract text content."""
    max_chars = _adaptive_max_chars(url, max_chars)

    if enable_github:
        # Auto-convert GitHub blob URLs to raw for reliable code extraction
        url = _github_blob_to_raw(url)

        # Try GitHub Contents API for directory/tree URLs
        api_url = _github_tree_to_api(url)
        if api_url:
            try:
                resp = requests.get(
                    api_url,
                    timeout=20,
                    headers={
                        "User-Agent": "Mozilla/5.0 (research bot)",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, list):
                    return _format_github_directory(data, repo_url=url)[:max_chars]
            except Exception:
                pass  # Fall through to normal HTML fetch

    if url.lower().rstrip("/").split("?")[0].endswith(".pdf"):
        return (
            "[PDF file — cannot extract text. "
            "Look for an HTML version of this content, or search for the project's "
            "GitHub repository to find source code with exploit details. "
            "Use web_search to find the repo, then fetch_url on the repo/directory URL "
            "to browse source files.]"
        )

    try:
        resp = requests.get(
            url, timeout=20, headers={"User-Agent": "Mozilla/5.0 (research bot)"}
        )
        resp.raise_for_status()
        content_type = resp.headers.get("content-type", "")

        if "pdf" in content_type:
            return "[PDF content — cannot extract text. Search for the project's GitHub repository instead.]"

        if "html" in content_type:
            try:
                from lxml import html as lxml_html

                doc = lxml_html.fromstring(resp.content)
                text = doc.text_content()
            except ImportError:
                from html.parser import HTMLParser

                class _TextExtractor(HTMLParser):
                    def __init__(self):
                        super().__init__()
                        self.parts = []

                    def handle_data(self, data):
                        self.parts.append(data)

                parser = _TextExtractor()
                parser.feed(resp.text)
                text = " ".join(parser.parts)
        else:
            text = resp.text

        # Clean up whitespace
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        text = "\n".join(lines)
        return text[:max_chars]
    except Exception as e:
        return f"Error fetching URL: {e}"


def get_web_tools(
    kb,
    target_vendor: str,
    target_protocol: str,
    enable_github: bool = True,
    config=None,
) -> dict:
    """Build web research tool registry."""
    if config is not None:
        enable_github = config.enable_github_fetch
        blocked_domains = config.blocked_domains
    else:
        blocked_domains = ()

    tools = {}

    # --- fetch_url ---
    def fetch_url(params):
        url = params["url"]
        max_chars = params.get("max_chars", 5000)
        # Note: fetch_url does not use disk caching (_get_cached / _set_cached).
        # Check domain restrictions on every call.
        if _is_url_blocked(url, blocked_domains):
            return f"We have blocked access to these websites: {', '.join(blocked_domains)}"
        text = _fetch_url_text(url, max_chars=max_chars, enable_github=enable_github)
        return text

    tools["fetch_url"] = (
        {
            "name": "fetch_url",
            "description": "Fetch and extract text content from a URL (CVE advisory, paper page, blog post). HTML is converted to plain text.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to fetch",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Maximum characters to return (default 5000)",
                    },
                },
                "required": ["url"],
            },
        },
        fetch_url,
    )

    # --- web_search ---
    def web_search(params):
        query = params["query"]
        max_results = params.get("max_results", 10)

        cache_k = _cache_key("websearch", query=query, max_results=max_results)
        cached = _get_cached(cache_k)
        if cached is not None:
            filtered = _filter_search_results(cached, blocked_domains)
            return json.dumps(filtered, indent=2)

        results = _web_search(query, max_results=max_results)

        if results and not any("error" in r for r in results):
            # Use shorter TTL for web search results
            os.makedirs(VULN_CACHE_PATH, exist_ok=True)
            path = os.path.join(VULN_CACHE_PATH, f"{cache_k}.json")
            with open(path, "w") as f:
                json.dump({"_cached_at": time.time(), "result": results}, f)

        filtered = _filter_search_results(results, blocked_domains)
        return json.dumps(filtered, indent=2)

    tools["web_search"] = (
        {
            "name": "web_search",
            "description": "Search the web for exploit write-ups, vulnerability reports, security advisories, and technical articles. Use fetch_url to read full content from promising results.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g. 'MediaTek modem CVE RRC crash', '5G baseband ASN.1 buffer overflow')",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return (default 10)",
                    },
                },
                "required": ["query"],
            },
        },
        web_search,
    )

    return tools
