import json


def get_memory_tools(kb, config=None):
    """Build memory tool registry.

    Args:
        config: VersionConfig. When config.load_global_kb is False,
                query_global_findings and promote_finding are not registered.
    """
    enable_global_kb = config is None or config.load_global_kb
    tools = {}

    # --- save_finding ---
    def save_finding(params):
        description = params["description"]
        tags = params.get("tags", [])
        related_tests = params.get("related_tests", [])
        entry = kb.save_finding(description, tags, related_tests)
        return json.dumps(entry, indent=2)

    tools["save_finding"] = (
        {
            "name": "save_finding",
            "description": "Store a finding with tags for future reference. Use to record observations, crash patterns, hypotheses, or dead ends.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Description of the finding",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tags for categorization (e.g. ['crash', 'rrc', 'hypothesis'])",
                    },
                    "related_tests": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Test IDs related to this finding",
                    },
                },
                "required": ["description"],
            },
        },
        save_finding,
    )

    # --- query_findings ---
    def query_findings(params):
        tag = params.get("tag")
        field = params.get("field")
        results = kb.query_findings(tag=tag, field=field)
        return json.dumps(results, indent=2)

    tools["query_findings"] = (
        {
            "name": "query_findings",
            "description": "Search stored findings by tag or field keyword.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "tag": {
                        "type": "string",
                        "description": "Filter by tag (e.g. 'crash', 'hypothesis')",
                    },
                    "field": {
                        "type": "string",
                        "description": "Filter by keyword in description (e.g. 'rrc', 'rnti')",
                    },
                },
            },
        },
        query_findings,
    )

    # --- get_test_history ---
    def get_test_history(params):
        limit = params.get("limit", 50)
        results = kb.get_test_history(limit=limit)
        return json.dumps(results, indent=2)

    tools["get_test_history"] = (
        {
            "name": "get_test_history",
            "description": "Get summary of recent tests: description, crash status, new states/transitions.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of recent tests to return (default 50)",
                    },
                },
            },
        },
        get_test_history,
    )

    # --- update_strategy ---
    def update_strategy(params):
        content = params["content"]
        kb.update_strategy(content)
        return json.dumps({"status": "Strategy updated", "length": len(content)})

    tools["update_strategy"] = (
        {
            "name": "update_strategy",
            "description": "Write or update your strategy memo. This is injected into your system prompt each turn, so use it to maintain continuity across context summarizations. Include: current focus, exhausted areas, promising leads.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Markdown content for the strategy memo",
                    }
                },
                "required": ["content"],
            },
        },
        update_strategy,
    )

    if enable_global_kb:
        # --- promote_finding ---
        def promote_finding(params):
            finding_id = params["finding_id"]
            result = kb.promote_finding(finding_id)
            if result is None:
                return json.dumps(
                    {"status": "not_found_or_duplicate", "finding_id": finding_id}
                )
            return json.dumps(
                {
                    "status": "promoted_to_global",
                    "finding_id": finding_id,
                    "entry": result,
                }
            )

        tools["promote_finding"] = (
            {
                "name": "promote_finding",
                "description": "Promote a session finding to the global knowledge base so it persists across runs. Use for important discoveries worth keeping permanently.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "integer",
                            "description": "The finding_id to promote to global KB",
                        },
                    },
                    "required": ["finding_id"],
                },
            },
            promote_finding,
        )

        # --- query_global_findings ---
        def query_global_findings(params):
            tag = params.get("tag")
            limit = params.get("limit", 50)
            results = kb.get_global_findings(tag=tag, limit=limit)
            return json.dumps(results, indent=2)

        tools["query_global_findings"] = (
            {
                "name": "query_global_findings",
                "description": "Search the global knowledge base (persists across all runs). Contains web-sourced vulnerability patterns and confirmed crashes from all sessions.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tag": {
                            "type": "string",
                            "description": "Filter by tag (e.g. 'crash', 'web_sourced', 'confirmed')",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results to return (default 50)",
                        },
                    },
                },
            },
            query_global_findings,
        )

    return tools
