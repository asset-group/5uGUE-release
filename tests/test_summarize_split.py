"""Test that _summarize_if_needed() doesn't orphan tool_result messages."""

from unittest.mock import MagicMock


def make_agent(messages):
    """Create a FuzzAgent with pre-set messages, bypassing __init__ deps."""
    from agent_core import FuzzAgent
    from version_config import get_version_config

    agent = FuzzAgent.__new__(FuzzAgent)
    agent.messages = messages
    agent.config = get_version_config("full")
    # Stub out what _summarize_if_needed calls besides splitting
    agent._estimate_tokens = MagicMock(return_value=999_999)
    agent._fix_message_order = MagicMock()
    return agent


def build_messages(pattern):
    """Build a message list from a role pattern string like 'u a t t u a u a t u a u a'.

    u=user, a=assistant, t=tool.  Assistant messages get a dummy tool_calls field.
    """
    msgs = []
    for role_char in pattern.split():
        if role_char == "u":
            msgs.append({"role": "user", "content": "user msg"})
        elif role_char == "a":
            msgs.append(
                {
                    "role": "assistant",
                    "content": "assistant msg",
                    "tool_calls": [
                        {
                            "id": f"call_{len(msgs)}",
                            "type": "function",
                            "function": {"name": "test", "arguments": "{}"},
                        }
                    ],
                }
            )
        elif role_char == "t":
            msgs.append(
                {
                    "role": "tool",
                    "tool_call_id": f"call_{len(msgs)}",
                    "content": "tool result",
                }
            )
    return msgs


class TestSummarizeSplitBoundary:
    """Verify the split never orphans tool messages from their parent assistant."""

    def test_no_orphaned_tool_at_split(self):
        """When messages[-6] is a tool message, split walks back to include parent assistant."""
        # 12 messages: u a t t u a u a t u a u
        # Index:       0 1 2 3 4 5 6 7 8 9 10 11
        # messages[-6] = index 6 (role=u) -- no problem here, let's craft one where -6 is tool
        #
        # 11 messages: u a u a t t u a u a u
        # Index:       0 1 2 3 4 5 6 7 8 9 10
        # messages[-6] = index 5 (role=t) -- this is the bug case
        msgs = build_messages("u a u a t t u a u a u")
        assert len(msgs) == 11
        assert msgs[5]["role"] == "tool"  # confirm -6 lands on tool

        agent = make_agent(msgs)
        agent._summarize_if_needed()

        # recent_messages should start with the assistant (index 3), not the tool (index 5)
        # After summarization: messages[0] = summary, messages[1:] = recent
        recent = agent.messages[1:]  # skip summary message
        assert recent[0]["role"] == "assistant", (
            f"Expected recent to start with assistant, got {recent[0]['role']}"
        )
        # The tool messages should follow their parent assistant
        assert recent[1]["role"] == "tool"
        assert recent[2]["role"] == "tool"

    def test_no_change_when_split_is_clean(self):
        """When messages[-6] is not a tool message, behavior is unchanged."""
        # 12 messages: u a t u a u a t u a u a
        # Index:       0 1 2 3 4 5 6 7 8 9 10 11
        # messages[-6] = index 6 (role=a) -- clean split
        msgs = build_messages("u a t u a u a t u a u a")
        assert len(msgs) == 12
        assert msgs[6]["role"] == "assistant"

        agent = make_agent(msgs)
        agent._summarize_if_needed()

        # recent = last 6 messages (unchanged behavior)
        recent = agent.messages[1:]
        assert len(recent) == 6

    def test_multiple_tool_results_walked_back(self):
        """Parallel tool calls: multiple tool results walked back to parent assistant."""
        # u a u a t t t u a u a u  (3 tool results from one assistant)
        # 0 1 2 3 4 5 6 7 8 9 10 11
        # messages[-6] = index 6 (tool)
        msgs = build_messages("u a u a t t t u a u a u")
        assert len(msgs) == 12
        assert msgs[6]["role"] == "tool"

        agent = make_agent(msgs)
        agent._summarize_if_needed()

        recent = agent.messages[1:]
        assert recent[0]["role"] == "assistant"
        assert all(recent[i]["role"] == "tool" for i in [1, 2, 3])

    def test_too_few_messages_skips(self):
        """With <= 8 messages, summarization is skipped entirely."""
        msgs = build_messages("u a t t u a u a")
        assert len(msgs) == 8

        agent = make_agent(msgs)
        original = list(msgs)
        agent._summarize_if_needed()

        assert agent.messages == original  # unchanged
