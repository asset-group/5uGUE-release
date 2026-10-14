"""Tests for web research tools (URL fetch, web search)."""

import json
import os
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.web_tools import (
    _cache_key,
    _fetch_url_text,
    _get_cached,
    _set_cached,
    get_web_tools,
)


class TestCaching:
    def test_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("tools.web_tools.VULN_CACHE_PATH", tmpdir):
                key = _cache_key("test", query="hello")
                _set_cached(key, [{"foo": "bar"}])
                result = _get_cached(key)
                assert result == [{"foo": "bar"}]

    def test_cache_miss(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("tools.web_tools.VULN_CACHE_PATH", tmpdir):
                result = _get_cached("nonexistent_key")
                assert result is None

    def test_cache_expired(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("tools.web_tools.VULN_CACHE_PATH", tmpdir):
                key = "expired_test"
                path = os.path.join(tmpdir, f"{key}.json")
                with open(path, "w") as f:
                    json.dump({"_cached_at": time.time() - 100000, "result": "old"}, f)
                result = _get_cached(key)
                assert result is None

    def test_cache_key_deterministic(self):
        k1 = _cache_key("nvd", keyword="test", max_results=5)
        k2 = _cache_key("nvd", keyword="test", max_results=5)
        assert k1 == k2

    def test_cache_key_different_params(self):
        k1 = _cache_key("nvd", keyword="test1")
        k2 = _cache_key("nvd", keyword="test2")
        assert k1 != k2


class TestFetchURL:
    @patch("tools.web_tools.requests.get")
    def test_fetch_html(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.text = "<html><body><p>Hello world</p></body></html>"
        mock_resp.content = b"<html><body><p>Hello world</p></body></html>"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        text = _fetch_url_text("https://example.com")
        assert "Hello world" in text

    @patch("tools.web_tools.requests.get")
    def test_fetch_plain_text(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/plain"}
        mock_resp.text = "Plain text content"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        text = _fetch_url_text("https://example.com/file.txt")
        assert text == "Plain text content"

    @patch("tools.web_tools.requests.get", side_effect=Exception("Connection error"))
    def test_fetch_error(self, mock_get):
        text = _fetch_url_text("https://bad.url")
        assert "Error" in text

    @patch("tools.web_tools.requests.get")
    def test_max_chars_truncation(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.headers = {"content-type": "text/plain"}
        mock_resp.text = "x" * 10000
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        text = _fetch_url_text("https://example.com", max_chars=100)
        assert len(text) <= 100


class TestGetWebTools:
    def test_tool_registry(self):
        kb = MagicMock()
        tools = get_web_tools(kb, "MediaTek", "5G NR")
        assert "fetch_url" in tools
        assert "web_search" in tools
        assert "search_cve" not in tools
        assert "search_vuln_patterns" not in tools

        # Each tool is (schema, handler) tuple
        for name, (schema, handler) in tools.items():
            assert schema["name"] == name
            assert "input_schema" in schema
            assert callable(handler)


class TestV3FDomainFiltering:
    def test_is_url_blocked_domain_matching(self):
        from tools.web_tools import _is_url_blocked

        blocked = (
            "github.com",
            "githubusercontent.com",
            "gitlab.com",
            "gitlab.io",
            "gitlab.org",
            "asset-group.github.io",
        )

        # GitHub matches
        assert _is_url_blocked("https://github.com/foo/bar", blocked)
        assert _is_url_blocked("https://raw.github.com/foo/bar", blocked)
        assert _is_url_blocked("https://a.a.github.com/foo/bar", blocked)
        assert _is_url_blocked("https://raw.githubusercontent.com/foo/bar", blocked)

        # GitLab matches
        assert _is_url_blocked("https://gitlab.com/group/project", blocked)
        assert _is_url_blocked("https://sub.gitlab.io/project", blocked)
        assert _is_url_blocked("https://gitlab.org/about", blocked)

        # asset-group.github.io matches
        assert _is_url_blocked("https://asset-group.github.io/5ghoul", blocked)
        assert _is_url_blocked("https://sub.asset-group.github.io/5ghoul", blocked)

        # Unaffected domains
        assert not _is_url_blocked("https://other-user.github.io/blog", blocked)
        assert not _is_url_blocked("https://nvd.nist.gov/vuln/detail/CVE-12345", blocked)
        assert not _is_url_blocked("https://example.com", blocked)

    def test_fetch_url_blocked_domain(self):
        from version_config import get_version_config

        kb = MagicMock()
        cfg_v3f = get_version_config("v3f")
        tools = get_web_tools(kb, "MediaTek", "5G NR", config=cfg_v3f)
        _, fetch_handler = tools["fetch_url"]

        expected_msg = f"We have blocked access to these websites: {', '.join(cfg_v3f.blocked_domains)}"

        res = fetch_handler({"url": "https://github.com/some/repo"})
        assert res == expected_msg

        res_asset = fetch_handler({"url": "https://asset-group.github.io/paper"})
        assert res_asset == expected_msg

    @patch("tools.web_tools._web_search")
    def test_web_search_filters_blocked_domains_and_cache(self, mock_search):
        from version_config import get_version_config

        kb = MagicMock()
        cfg_v3f = get_version_config("v3f")
        tools = get_web_tools(kb, "MediaTek", "5G NR", config=cfg_v3f)
        _, search_handler = tools["web_search"]

        # Mock search return containing a blocked link and an allowed link
        mock_search.return_value = [
            {"title": "GitHub Exploit", "url": "https://github.com/foo/exploit", "snippet": "code"},
            {"title": "NVD Advisory", "url": "https://nvd.nist.gov/detail", "snippet": "cve"},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("tools.web_tools.VULN_CACHE_PATH", tmpdir):
                # First search: returns filtered results
                res_str = search_handler({"query": "MediaTek RRC CVE"})
                res_data = json.loads(res_str)
                assert len(res_data) == 1
                assert res_data[0]["url"] == "https://nvd.nist.gov/detail"

                # Second search (disk cache hit): filtering is still enforced post-cache-read
                res_cache_str = search_handler({"query": "MediaTek RRC CVE"})
                res_cache_data = json.loads(res_cache_str)
                assert len(res_cache_data) == 1
                assert res_cache_data[0]["url"] == "https://nvd.nist.gov/detail"

