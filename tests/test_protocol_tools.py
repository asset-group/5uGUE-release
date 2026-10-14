"""Test protocol tools (glossary lookup, field search)."""

import json


class TestSearchFields:
    def test_search_rrc(self):
        from tools.protocol_tools import get_protocol_tools

        tools = get_protocol_tools()
        _, handler = tools["search_fields"]
        result = json.loads(handler({"keyword": "rrc", "max_results": 10}))
        assert len(result) > 0
        assert all("field" in m and "description" in m for m in result)

    def test_search_security(self):
        from tools.protocol_tools import get_protocol_tools

        tools = get_protocol_tools()
        _, handler = tools["search_fields"]
        result = json.loads(handler({"keyword": "security", "max_results": 5}))
        assert len(result) > 0

    def test_search_no_results(self):
        from tools.protocol_tools import get_protocol_tools

        tools = get_protocol_tools()
        _, handler = tools["search_fields"]
        result = json.loads(handler({"keyword": "zzzznonexistentzzzz"}))
        assert result == []
