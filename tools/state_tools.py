import json
import logging
import os

from upstream.utils.state_transition import gen_sm

logger = logging.getLogger(__name__)


def get_state_tools(wd_tool):
    tools = {}

    # --- view_state_machine ---
    def view_state_machine(params):
        capture_path = params["capture_path"]
        if not os.path.isabs(capture_path):
            capture_path = os.path.abspath(capture_path)

        sm = gen_sm(wd_tool, capture_path)

        states = list(sm.states.keys())
        transitions = []
        for state_name, state in sm.states.items():
            for next_name in state.next_states:
                transitions.append(f"{state_name} -> {next_name}")

        return json.dumps(
            {
                "total_states": len(states),
                "states": states,
                "total_transitions": len(transitions),
                "transitions": transitions,
            },
            indent=2,
        )

    tools["view_state_machine"] = (
        {
            "name": "view_state_machine",
            "description": "Generate and view the full state machine graph from a capture file. Shows all states and transitions observed.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "capture_path": {
                        "type": "string",
                        "description": "Absolute path to the pcapng capture file",
                    }
                },
                "required": ["capture_path"],
            },
        },
        view_state_machine,
    )

    # --- diff_state_machines ---
    def diff_state_machines(params):
        baseline_path = params["baseline_path"]
        test_path = params["test_path"]

        if not os.path.isabs(baseline_path):
            baseline_path = os.path.abspath(baseline_path)
        if not os.path.isabs(test_path):
            test_path = os.path.abspath(test_path)

        from upstream.llm_fuzz import new_states_and_transitions

        base_sm = gen_sm(wd_tool, baseline_path)
        new_states, new_transitions = new_states_and_transitions(
            wd_tool, base_sm, test_path
        )

        return json.dumps(
            {
                "new_states": new_states,
                "new_transitions": new_transitions,
                "baseline_states_count": len(base_sm.states),
            },
            indent=2,
        )

    # Commented out: never used in any run
    # tools["diff_state_machines"] = (
    #     {
    #         "name": "diff_state_machines",
    #         "description": "Compare baseline vs test capture, returning any new states or transitions discovered during the test.",
    #         "input_schema": {
    #             "type": "object",
    #             "properties": {
    #                 "baseline_path": {
    #                     "type": "string",
    #                     "description": "Absolute path to the baseline pcapng capture file",
    #                 },
    #                 "test_path": {
    #                     "type": "string",
    #                     "description": "Absolute path to the test pcapng capture file",
    #                 },
    #             },
    #             "required": ["baseline_path", "test_path"],
    #         },
    #     },
    #     diff_state_machines,
    # )

    return tools
