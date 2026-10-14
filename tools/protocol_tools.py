import json
import logging
import os

from constants import FIVEG_FIELDS_DESC

logger = logging.getLogger(__name__)


def get_protocol_tools():
    tools = {}

    # Load field descriptions
    _fields_desc = {}
    if os.path.exists(FIVEG_FIELDS_DESC):
        with open(FIVEG_FIELDS_DESC, "r", encoding="utf8") as f:
            _fields_desc = json.load(f)

    # --- lookup_field_description ---
    def lookup_field_description(params):
        field_names = params["field_names"]
        results = {}
        for name in field_names:
            if name in _fields_desc:
                results[name] = _fields_desc[name]
            else:
                results[name] = "No description available"
        return json.dumps(results, indent=2)

    # Commented out: never used in any run — get_field_info covers this
    # tools["lookup_field_description"] = (
    #     {
    #         "name": "lookup_field_description",
    #         "description": "Get descriptions for specific 5G NR protocol fields from the glossary.",
    #         "input_schema": {
    #             "type": "object",
    #             "properties": {
    #                 "field_names": {
    #                     "type": "array",
    #                     "items": {"type": "string"},
    #                     "description": "List of field names (e.g. ['mac-nr.rnti', 'nr-rrc.spare_bit'])",
    #                 }
    #             },
    #             "required": ["field_names"],
    #         },
    #     },
    #     lookup_field_description,
    # )

    # --- search_fields ---
    def search_fields(params):
        keyword = params["keyword"].lower()
        max_results = params.get("max_results", 30)

        matches = []
        for name, desc in _fields_desc.items():
            if keyword in name.lower() or keyword in desc.lower():
                matches.append({"field": name, "description": desc[:120]})
            if len(matches) >= max_results:
                break

        return json.dumps(matches, indent=2)

    tools["search_fields"] = (
        {
            "name": "search_fields",
            "description": "Search field names and descriptions by keyword (e.g. 'rrc', 'nas', 'security', 'rnti').",
            "input_schema": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Keyword to search for in field names and descriptions",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return (default 30)",
                    },
                },
                "required": ["keyword"],
            },
        },
        search_fields,
    )

    # --- get_field_valid_range ---
    def get_field_valid_range(params):
        field_name = params["field_name"]
        desc = _fields_desc.get(field_name, "No description available")
        # Provide what info we can from the name and description
        info = {
            "field_name": field_name,
            "description": desc,
            "note": "Use get_field_info with a capture file to get exact bitmask size. "
            "The valid range is 0 to (2^bit_width - 1) based on the bitmask.",
        }
        return json.dumps(info, indent=2)

    # Commented out: never used — agent infers ranges from packet inspection
    # tools["get_field_valid_range"] = (
    #     {
    #         "name": "get_field_valid_range",
    #         "description": "Get description and range hints for a protocol field.",
    #         "input_schema": {
    #             "type": "object",
    #             "properties": {
    #                 "field_name": {
    #                     "type": "string",
    #                     "description": "Wireshark field name",
    #                 }
    #             },
    #             "required": ["field_name"],
    #         },
    #     },
    #     get_field_valid_range,
    # )

    return tools
