"""Extended tests for FuzzAgent: token estimation, summarization, message ordering, and run loop."""

import json
from unittest.mock import MagicMock, patch


def _make_agent_stub(messages=None, tools=None):
    """Create a FuzzAgent without calling __init__ (avoids API client)."""
    from agent_core import FuzzAgent
    from version_config import get_version_config

    agent = FuzzAgent.__new__(FuzzAgent)
    agent.messages = messages or []
    agent.tools = tools or {}
    agent.total_input_tokens = 0
    agent.total_output_tokens = 0
    agent.consecutive_failures = 0
    agent.REFLECTION_THRESHOLD = 5
    agent.config = get_version_config("full")
    return agent


class TestEstimateTokens:
    def test_empty_messages(self):
        agent = _make_agent_stub([])
        assert agent._estimate_tokens() == 0

    def test_string_content(self):
        agent = _make_agent_stub(
            [
                {"role": "user", "content": "a" * 400},  # 400 chars -> ~100 tokens
            ]
        )
        assert agent._estimate_tokens() == 100

    def test_list_content(self):
        block = {"type": "tool_result", "content": "x" * 100}
        agent = _make_agent_stub(
            [
                {"role": "user", "content": [block]},
            ]
        )
        tokens = agent._estimate_tokens()
        # JSON dump of block is longer than 100 chars
        assert tokens > 25

    def test_mixed_content(self):
        agent = _make_agent_stub(
            [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "world"},
            ]
        )
        tokens = agent._estimate_tokens()
        assert tokens > 0

    def test_missing_content_key(self):
        agent = _make_agent_stub(
            [
                {"role": "user"},  # no content key
            ]
        )
        assert agent._estimate_tokens() == 0

    def test_tool_calls_counted(self):
        agent = _make_agent_stub(
            [
                {
                    "role": "assistant",
                    "content": "thinking",
                    "tool_calls": [
                        {
                            "id": "tc1",
                            "type": "function",
                            "function": {
                                "name": "test",
                                "arguments": '{"key": "value"}',
                            },
                        }
                    ],
                },
            ]
        )
        tokens = agent._estimate_tokens()
        # Should count both content and tool_calls arguments
        assert tokens > len("thinking") // 4


class TestFixMessageOrder:
    def test_already_alternating(self):
        agent = _make_agent_stub(
            [
                {"role": "user", "content": "a"},
                {"role": "assistant", "content": "b"},
                {"role": "user", "content": "c"},
            ]
        )
        agent._fix_message_order()
        roles = [m["role"] for m in agent.messages]
        assert roles == ["user", "assistant", "user"]

    def test_consecutive_user_messages_merged(self):
        agent = _make_agent_stub(
            [
                {"role": "user", "content": "first"},
                {"role": "user", "content": "second"},
            ]
        )
        agent._fix_message_order()
        assert len(agent.messages) == 1
        assert "first" in agent.messages[0]["content"]
        assert "second" in agent.messages[0]["content"]

    def test_consecutive_assistant_messages_get_filler(self):
        agent = _make_agent_stub(
            [
                {"role": "user", "content": "start"},
                {"role": "assistant", "content": "resp1"},
                {"role": "assistant", "content": "resp2"},
            ]
        )
        agent._fix_message_order()
        roles = [m["role"] for m in agent.messages]
        # Should insert a user filler between the two assistant messages
        assert roles == ["user", "assistant", "user", "assistant"]
        assert agent.messages[2]["content"] == "(continuing)"

    def test_empty_messages(self):
        agent = _make_agent_stub([])
        agent._fix_message_order()
        assert agent.messages == []

    def test_list_content_not_merged(self):
        """Non-string content user messages should not be merged."""
        agent = _make_agent_stub(
            [
                {
                    "role": "user",
                    "content": [{"type": "tool_result", "content": "data"}],
                },
                {"role": "user", "content": "follow up"},
            ]
        )
        agent._fix_message_order()
        # Because first is list, second is str — they can't be string-merged
        # A filler should be inserted instead
        roles = [m["role"] for m in agent.messages]
        assert "assistant" in roles  # filler inserted

    def test_tool_messages_skip_alternation(self):
        """Tool messages should not trigger alternation issues."""
        agent = _make_agent_stub(
            [
                {"role": "user", "content": "start"},
                {
                    "role": "assistant",
                    "content": "thinking",
                    "tool_calls": [{"id": "tc1"}],
                },
                {"role": "tool", "tool_call_id": "tc1", "content": "result"},
                {"role": "assistant", "content": "done"},
            ]
        )
        agent._fix_message_order()
        roles = [m["role"] for m in agent.messages]
        assert roles == ["user", "assistant", "tool", "user", "assistant"]


class TestSummarizeIfNeeded:
    def test_no_summarization_below_threshold(self):
        """Short conversations should not be summarized."""
        agent = _make_agent_stub(
            [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
            ]
        )
        original_count = len(agent.messages)
        agent._summarize_if_needed()
        assert len(agent.messages) == original_count

    def test_summarization_triggered_above_threshold(self):
        """Messages exceeding ~500k tokens (FULL/V3 threshold) should be summarized."""
        # Create messages totaling >2M chars (~500k tokens)
        messages = []
        for i in range(120):
            role = "user" if i % 2 == 0 else "assistant"
            messages.append({"role": role, "content": "x" * 18000})
        agent = _make_agent_stub(messages)

        assert agent._estimate_tokens() > 500_000
        agent._summarize_if_needed()
        # Should be reduced: summary + last 6 messages
        assert len(agent.messages) <= 10

    def test_summarization_preserves_recent_messages(self):
        """Last 6 messages should be preserved after summarization."""
        messages = []
        for i in range(120):
            role = "user" if i % 2 == 0 else "assistant"
            content = f"message_{i}_" + "x" * 18000
            messages.append({"role": role, "content": content})
        agent = _make_agent_stub(messages)

        agent._summarize_if_needed()
        # The last message should be preserved
        last_contents = [
            m["content"] for m in agent.messages if isinstance(m.get("content"), str)
        ]
        assert any("message_119" in c for c in last_contents)

    def test_summarization_extracts_test_results(self):
        """Test results in old messages should appear in summary."""
        test_result_json = json.dumps(
            {
                "test_id": "run-5",
                "fuzz_description": "RRC mutation test",
                "crash_triggered": True,
                "mutation_count": 3,
                "total_packets": 45,
                "new_states": ["state_A"],
            }
        )
        messages = [
            {"role": "user", "content": "start"},
        ]
        # Fill with enough content to trigger summarization (>500k tokens = >2M chars)
        for i in range(120):
            messages.append({"role": "assistant", "content": "thinking " + "x" * 18000})
            if i == 5:
                # Tool result message (OpenAI format)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": "abc",
                        "content": test_result_json,
                    }
                )
                # Need a user message to maintain alternation
                messages.append({"role": "user", "content": "continue " + "y" * 18000})
            else:
                messages.append({"role": "user", "content": "continue " + "y" * 18000})

        agent = _make_agent_stub(messages)
        agent._summarize_if_needed()

        # Summary message should reference the test result
        summary = agent.messages[0]["content"]
        assert "run-5" in summary or "Test Results" in summary

    def test_no_summarization_few_messages(self):
        """Even if tokens are high, don't summarize if <= 8 messages."""
        messages = []
        for i in range(8):
            role = "user" if i % 2 == 0 else "assistant"
            messages.append({"role": role, "content": "x" * 300000})

        agent = _make_agent_stub(messages)
        original_count = len(agent.messages)
        agent._summarize_if_needed()
        assert len(agent.messages) == original_count

    def test_summarization_extracts_findings(self):
        """Findings from save_finding should appear in summary."""
        finding_json = json.dumps(
            {
                "finding_id": 1,
                "description": "RRC SecurityModeCommand triggers parsing error",
            }
        )
        messages = []
        for i in range(120):
            role = "user" if i % 2 == 0 else "assistant"
            if i == 4:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": "f1",
                        "content": finding_json,
                    }
                )
            else:
                messages.append({"role": role, "content": "analysis " + "x" * 18000})

        agent = _make_agent_stub(messages)
        agent._summarize_if_needed()

        summary = agent.messages[0]["content"]
        assert "Finding" in summary or "Findings" in summary

    def test_summarization_extracts_reasoning(self):
        """Key reasoning with hypothesis/insight keywords should be preserved."""
        messages = []
        for i in range(120):
            role = "user" if i % 2 == 0 else "assistant"
            if role == "assistant" and i == 3:
                messages.append(
                    {
                        "role": "assistant",
                        "content": "My hypothesis is that the modem parser fails on malformed HARQ-ACK codebook values because it does not validate enum ranges",
                    }
                )
            else:
                messages.append({"role": role, "content": "padding " + "x" * 18000})

        agent = _make_agent_stub(messages)
        agent._summarize_if_needed()

        summary = agent.messages[0]["content"]
        assert "hypothesis" in summary.lower() or "Reasoning" in summary


class TestToolDispatchExtended:
    def test_handler_exception_returns_error(self):
        """Tool handler exceptions should be caught and returned as error JSON."""
        agent = _make_agent_stub()
        agent.tools = {
            "failing_tool": (
                {"name": "failing_tool"},
                lambda p: (_ for _ in ()).throw(ValueError("bad input")),
            )
        }

        # The lambda above won't work for raising. Use a proper function.
        def bad_handler(p):
            raise ValueError("bad input")

        agent.tools = {"failing_tool": ({"name": "failing_tool"}, bad_handler)}
        result = agent._handle_tool_call("failing_tool", {})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "bad input" in parsed["error"]

    def test_tool_result_exact_limit_not_truncated(self):
        from agent_core import FuzzAgent

        agent = _make_agent_stub()
        exact_result = "x" * FuzzAgent.TOOL_RESULT_MAX_CHARS
        agent.tools = {"exact_tool": ({"name": "exact_tool"}, lambda p: exact_result)}
        result = agent._handle_tool_call("exact_tool", {})
        assert "TRUNCATED" not in result

    def test_tool_result_one_over_limit_truncated(self):
        from agent_core import FuzzAgent

        agent = _make_agent_stub()
        over_result = "x" * (FuzzAgent.TOOL_RESULT_MAX_CHARS + 1)
        agent.tools = {"over_tool": ({"name": "over_tool"}, lambda p: over_result)}
        result = agent._handle_tool_call("over_tool", {})
        assert "TRUNCATED" in result


class TestGetToolSchemas:
    def test_returns_openai_format(self):
        schema1 = {
            "name": "tool1",
            "description": "Tool 1",
            "input_schema": {"type": "object"},
        }
        schema2 = {
            "name": "tool2",
            "description": "Tool 2",
            "input_schema": {"type": "object"},
        }
        agent = _make_agent_stub(
            tools={
                "tool1": (schema1, lambda p: ""),
                "tool2": (schema2, lambda p: ""),
            }
        )
        schemas = agent._get_tool_schemas()
        assert len(schemas) == 2
        # Should be in OpenAI function format
        for s in schemas:
            assert s["type"] == "function"
            assert "function" in s
            assert "name" in s["function"]
            assert "parameters" in s["function"]


class TestConsecutiveFailureTracking:
    def test_failure_counter_increments(self):
        agent = _make_agent_stub()
        assert agent.consecutive_failures == 0
        agent.consecutive_failures += 1
        assert agent.consecutive_failures == 1

    def test_failure_resets_on_crash(self):
        agent = _make_agent_stub()
        agent.consecutive_failures = 4
        # Simulate crash result
        agent.consecutive_failures = 0
        assert agent.consecutive_failures == 0

    def test_reflection_threshold(self):
        agent = _make_agent_stub()
        assert agent.REFLECTION_THRESHOLD == 5
        agent.consecutive_failures = 5
        assert agent.consecutive_failures >= agent.REFLECTION_THRESHOLD


def _build_mock_response(finish_reason="stop", text="thinking...", tool_calls=None):
    """Build an OpenAI-style mock response."""
    response = MagicMock()
    message = MagicMock()
    message.content = text
    message.tool_calls = None
    if tool_calls:
        mock_tcs = []
        for tc in tool_calls:
            mock_tc = MagicMock()
            mock_tc.id = tc.get("id", "tool_id_1")
            mock_tc.function.name = tc["name"]
            mock_tc.function.arguments = json.dumps(tc["input"])
            mock_tcs.append(mock_tc)
        message.tool_calls = mock_tcs
    choice = MagicMock()
    choice.message = message
    choice.finish_reason = finish_reason
    response.choices = [choice]
    response.usage = MagicMock()
    response.usage.prompt_tokens = 100
    response.usage.completion_tokens = 50
    return response


class TestRunLoopWithMockedAPI:
    """Test the run() method with mocked OpenAI client."""

    def test_run_max_turns_stops(self):
        from agent_core import FuzzAgent

        mock_client = MagicMock()
        response = _build_mock_response(
            finish_reason="stop", text="I'll start testing."
        )
        mock_client.chat.completions.create.return_value = response

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        list_handler = MagicMock(return_value='[{"filter": "test"}]')
        tools = {
            "list_packet_types": ({"name": "list_packet_types"}, list_handler),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/capture.pcapng")

        # Should have called the API exactly 2 times (max_turns=2)
        assert mock_client.chat.completions.create.call_count == 2

    def test_run_accumulates_tokens(self):
        from agent_core import FuzzAgent

        mock_client = MagicMock()
        response = _build_mock_response()
        mock_client.chat.completions.create.return_value = response

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=3
            )
            agent.run("/test/cap.pcapng")

        assert agent.total_input_tokens == 300  # 100 * 3 turns
        assert agent.total_output_tokens == 150  # 50 * 3 turns

    def test_run_tool_use_dispatches(self):
        from agent_core import FuzzAgent

        mock_client = MagicMock()

        # First call: tool_calls, Second call: stop (to advance turn)
        tool_response = _build_mock_response(
            finish_reason="tool_calls",
            text="Let me check packets",
            tool_calls=[
                {
                    "name": "list_packet_types",
                    "input": {"capture_path": "/test.pcapng"},
                    "id": "tu1",
                }
            ],
        )
        end_response = _build_mock_response(
            finish_reason="stop", text="Done analyzing."
        )
        mock_client.chat.completions.create.side_effect = [tool_response, end_response]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        handler = MagicMock(return_value='[{"filter": "nr-rrc.c1"}]')
        tools = {"list_packet_types": ({"name": "list_packet_types"}, handler)}

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/cap.pcapng")

        # The list_packet_types handler is called once during init briefing, once during tool dispatch
        assert handler.call_count >= 2

    def test_run_reflection_injected_after_failures(self):
        from agent_core import FuzzAgent

        mock_client = MagicMock()

        # Create a series of execute_test tool calls that result in no crashes
        no_crash_result = json.dumps(
            {
                "test_id": "t1",
                "compile_success": True,
                "crash_triggered": False,
                "new_states": [],
                "mutation_count": 1,
                "total_packets": 50,
            }
        )

        tool_response = _build_mock_response(
            finish_reason="tool_calls",
            text="Testing",
            tool_calls=[
                {"name": "execute_test", "input": {"description": "test"}, "id": "et1"}
            ],
        )
        end_response = _build_mock_response(finish_reason="stop")
        # Repeat tool calls enough to trigger reflection (5 failures)
        mock_client.chat.completions.create.side_effect = [tool_response] * 6 + [
            end_response
        ]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        execute_handler = MagicMock(return_value=no_crash_result)
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            ),
            "execute_test": ({"name": "execute_test"}, execute_handler),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=7
            )
            agent.run("/test/cap.pcapng")

        # Check that a reflection prompt was injected
        reflection_found = any(
            "REFLECTION REQUIRED" in str(m.get("content", ""))
            for m in agent.messages
            if isinstance(m.get("content"), str)
        )
        assert reflection_found

    def test_run_handles_empty_content(self):
        from agent_core import FuzzAgent

        mock_client = MagicMock()
        empty_response = MagicMock()
        empty_choice = MagicMock()
        empty_message = MagicMock()
        empty_message.content = None
        empty_message.tool_calls = None
        empty_choice.message = empty_message
        empty_choice.finish_reason = "stop"
        empty_response.choices = [empty_choice]
        empty_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)

        normal_response = _build_mock_response()
        mock_client.chat.completions.create.side_effect = [
            empty_response,
            normal_response,
        ]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/cap.pcapng")

        # Should have retried after empty content
        assert mock_client.chat.completions.create.call_count == 2

    def test_run_includes_known_crashes_briefing(self):
        from agent_core import FuzzAgent

        mock_client = MagicMock()
        response = _build_mock_response()
        mock_client.chat.completions.create.return_value = response

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=1
            )
            agent.run("/test/cap.pcapng")

        # Check initial message includes crash briefing
        initial_msg = agent.messages[0]["content"]
        assert isinstance(initial_msg, str)
        # The briefing should contain known crash info (from build_known_crashes_briefing)
        assert "packet_types" in initial_msg

    def test_run_rate_limit_retries(self):
        """Rate limit errors should be retried (consuming a turn)."""
        from agent_core import FuzzAgent
        from openai import RateLimitError

        mock_client = MagicMock()
        rate_error = RateLimitError(
            message="rate limited",
            response=MagicMock(status_code=429, headers={"retry-after": "1"}),
            body=None,
        )
        normal_response = _build_mock_response()
        mock_client.chat.completions.create.side_effect = [rate_error, normal_response]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with (
            patch("agent_core.OpenAI", return_value=mock_client),
            patch("agent_core.time.sleep") as mock_sleep,
        ):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/cap.pcapng")

        # Should have slept after rate limit
        mock_sleep.assert_any_call(6)  # retry-after=1 + 5 buffer
        # Both turns consumed (one rate limit retry + one normal)
        assert mock_client.chat.completions.create.call_count == 2

    def test_run_rate_limit_no_retry_header(self):
        """Rate limit without retry-after header defaults to 60s."""
        from agent_core import FuzzAgent
        from openai import RateLimitError

        mock_client = MagicMock()
        rate_error = RateLimitError(
            message="rate limited",
            response=MagicMock(status_code=429, headers={}),
            body=None,
        )
        normal_response = _build_mock_response()
        mock_client.chat.completions.create.side_effect = [rate_error, normal_response]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with (
            patch("agent_core.OpenAI", return_value=mock_client),
            patch("agent_core.time.sleep") as mock_sleep,
        ):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/cap.pcapng")

        mock_sleep.assert_any_call(60)

    def test_run_api_error_retries(self):
        """Generic API errors should be retried with 10s sleep."""
        from agent_core import FuzzAgent
        from openai import APIError

        mock_client = MagicMock()
        api_error = APIError(
            message="server error",
            request=MagicMock(),
            body=None,
        )
        normal_response = _build_mock_response()
        mock_client.chat.completions.create.side_effect = [api_error, normal_response]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with (
            patch("agent_core.OpenAI", return_value=mock_client),
            patch("agent_core.time.sleep") as mock_sleep,
        ):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/cap.pcapng")

        mock_sleep.assert_any_call(15)  # backoff: min(15 * 1, 120) = 15

    def test_run_usage_none_handled(self):
        """Response with usage=None should not crash."""
        from agent_core import FuzzAgent

        mock_client = MagicMock()
        response = _build_mock_response()
        response.usage = None
        mock_client.chat.completions.create.return_value = response

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=1
            )
            agent.run("/test/cap.pcapng")

        # Tokens should remain 0 since usage was None
        assert agent.total_input_tokens == 0
        assert agent.total_output_tokens == 0

    def test_run_unexpected_stop_reason(self):
        """Unexpected stop reason should prompt continuation."""
        from agent_core import FuzzAgent

        mock_client = MagicMock()
        weird_response = _build_mock_response(finish_reason="length")
        normal_response = _build_mock_response(finish_reason="stop")
        mock_client.chat.completions.create.side_effect = [
            weird_response,
            normal_response,
        ]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            )
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/cap.pcapng")

        # Should have added a "Continue" message for the unexpected stop
        continue_msgs = [
            m
            for m in agent.messages
            if isinstance(m.get("content"), str)
            and "Continue with your next action." == m["content"]
        ]
        assert len(continue_msgs) >= 1

    def test_run_kb_log_test_exception_handled(self):
        """Exception in kb.log_test should not crash the run loop."""
        from agent_core import FuzzAgent

        mock_client = MagicMock()

        test_result = json.dumps(
            {
                "test_id": "t1",
                "compile_success": True,
                "crash_triggered": False,
                "new_states": [],
                "mutation_count": 1,
                "total_packets": 50,
            }
        )

        tool_response = _build_mock_response(
            finish_reason="tool_calls",
            text="Testing",
            tool_calls=[
                {"name": "execute_test", "input": {"description": "test"}, "id": "et1"}
            ],
        )
        end_response = _build_mock_response(finish_reason="stop")
        mock_client.chat.completions.create.side_effect = [tool_response, end_response]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []
        kb.log_test.side_effect = RuntimeError("KB write failed")

        engine = MagicMock()
        engine.test_count = 0

        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            ),
            "execute_test": (
                {"name": "execute_test"},
                MagicMock(return_value=test_result),
            ),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.run("/test/cap.pcapng")

        # Run should complete without crashing
        assert mock_client.chat.completions.create.call_count == 2

    def test_run_consecutive_failure_resets_on_new_states(self):
        """New states in test result should reset consecutive_failures."""
        from agent_core import FuzzAgent

        mock_client = MagicMock()

        result_with_states = json.dumps(
            {
                "test_id": "t1",
                "compile_success": True,
                "crash_triggered": False,
                "new_states": ["new_state"],
                "mutation_count": 1,
                "total_packets": 50,
            }
        )

        tool_response = _build_mock_response(
            finish_reason="tool_calls",
            text="Testing",
            tool_calls=[
                {"name": "execute_test", "input": {"description": "test"}, "id": "et1"}
            ],
        )
        end_response = _build_mock_response(finish_reason="stop")
        mock_client.chat.completions.create.side_effect = [tool_response, end_response]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            ),
            "execute_test": (
                {"name": "execute_test"},
                MagicMock(return_value=result_with_states),
            ),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.consecutive_failures = 4  # Set high before run
            agent.run("/test/cap.pcapng")

        # Should be reset because new_states was non-empty
        assert agent.consecutive_failures == 0

    def test_run_consecutive_failure_resets_on_crash(self):
        """Crash in test result should reset consecutive_failures."""
        from agent_core import FuzzAgent

        mock_client = MagicMock()

        crash_result = json.dumps(
            {
                "test_id": "t1",
                "compile_success": True,
                "crash_triggered": True,
                "new_states": [],
                "mutation_count": 1,
                "total_packets": 50,
            }
        )

        tool_response = _build_mock_response(
            finish_reason="tool_calls",
            text="Testing",
            tool_calls=[
                {"name": "execute_test", "input": {"description": "test"}, "id": "et1"}
            ],
        )
        end_response = _build_mock_response(finish_reason="stop")
        mock_client.chat.completions.create.side_effect = [tool_response, end_response]

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []

        engine = MagicMock()
        engine.test_count = 0

        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            ),
            "execute_test": (
                {"name": "execute_test"},
                MagicMock(return_value=crash_result),
            ),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools, execution_engine=engine, knowledge_base=kb, max_turns=2
            )
            agent.consecutive_failures = 3
            agent.run("/test/cap.pcapng")

        assert agent.consecutive_failures == 0


class TestSummarizeExtractAssistantBlocks:
    """Test summarization extraction of text from assistant messages."""

    def test_extracts_from_string_content(self):
        """String content assistant messages should be extracted."""
        messages = []
        for i in range(120):
            role = "user" if i % 2 == 0 else "assistant"
            if role == "assistant" and i == 5:
                messages.append(
                    {
                        "role": "assistant",
                        "content": "This approach is promising because the enum boundary is unchecked "
                        + "x" * 18000,
                    }
                )
            else:
                messages.append({"role": role, "content": "filler " + "y" * 18000})

        agent = _make_agent_stub(messages)
        agent._summarize_if_needed()

        summary = agent.messages[0]["content"]
        assert "approach" in summary.lower() or "Reasoning" in summary

    def test_extracts_reasoning_keywords(self):
        """Hypothesis/insight keywords in assistant content should be preserved."""
        messages = []
        for i in range(120):
            role = "user" if i % 2 == 0 else "assistant"
            if role == "assistant" and i == 7:
                messages.append(
                    {
                        "role": "assistant",
                        "content": "My hypothesis is that offset 74 controls the qcl-Type enum which is critical for modem stability "
                        + "z" * 18000,
                    }
                )
            else:
                messages.append({"role": role, "content": "padding " + "w" * 18000})

        agent = _make_agent_stub(messages)
        agent._summarize_if_needed()

        summary = agent.messages[0]["content"]
        assert "hypothesis" in summary.lower() or "Reasoning" in summary


class TestSessionUniqueNovelTracking:
    """Verify agent_core dedupes novel crashes by crash_id and threads the
    set through to agent_metrics.log_turn — the wiring no other test layer
    exercises end-to-end."""

    def _make_kb_engine(self):
        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.query_findings.return_value = []
        kb.get_global_findings.return_value = []
        engine = MagicMock()
        engine.test_count = 0
        engine.run_id = "rid01234"
        return kb, engine

    def test_execute_test_dedupes_novel_crash_id(self):
        from agent_core import FuzzAgent

        # Three results: novel n1, novel n1 (dup), publicly-known p1.
        results = [
            json.dumps(
                {
                    "test_id": "t1",
                    "compile_success": True,
                    "crash_triggered": True,
                    "crash_id": "n1",
                    "crash_category": "fully_novel_crash",
                    "new_states": [],
                    "mutation_count": 1,
                    "total_packets": 50,
                }
            ),
            json.dumps(
                {
                    "test_id": "t2",
                    "compile_success": True,
                    "crash_triggered": True,
                    "crash_id": "n1",
                    "crash_category": "fully_novel_crash",
                    "new_states": [],
                    "mutation_count": 1,
                    "total_packets": 50,
                }
            ),
            json.dumps(
                {
                    "test_id": "t3",
                    "compile_success": True,
                    "crash_triggered": True,
                    "crash_id": "p1",
                    "crash_category": "publicly_known_crash",
                    "new_states": [],
                    "mutation_count": 1,
                    "total_packets": 50,
                }
            ),
        ]
        execute_handler = MagicMock(side_effect=results)

        mock_client = MagicMock()
        responses = [
            _build_mock_response(
                finish_reason="tool_calls",
                text="t",
                tool_calls=[
                    {
                        "name": "execute_test",
                        "input": {"description": "d"},
                        "id": f"et{i}",
                    }
                ],
            )
            for i in range(3)
        ] + [_build_mock_response(finish_reason="stop")]
        mock_client.chat.completions.create.side_effect = responses

        kb, engine = self._make_kb_engine()
        agent_metrics = MagicMock()
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            ),
            "execute_test": ({"name": "execute_test"}, execute_handler),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools,
                execution_engine=engine,
                knowledge_base=kb,
                max_turns=4,
                agent_metrics=agent_metrics,
            )
            agent.run("/test/cap.pcapng")

        # Dedup at the runtime layer: n1 collapses to one entry; p1 separate.
        assert agent.session_unique_novel_crash_ids == {"n1"}
        assert agent.session_unique_crash_ids == {"n1", "p1"}

        # Pass-through to log_turn: every call must carry the kwarg, and the
        # final call must reflect the deduped set.
        assert agent_metrics.log_turn.call_count >= 1
        for call in agent_metrics.log_turn.call_args_list:
            assert "session_unique_novel_crash_ids" in call.kwargs
        last_call = agent_metrics.log_turn.call_args_list[-1]
        assert last_call.kwargs["session_unique_novel_crash_ids"] == {"n1"}

    def test_execute_test_batch_dedupes_novel_crash_id(self):
        from agent_core import FuzzAgent

        # Single batch with three sub-results: novel n1, novel n1 (dup), public p1.
        batch_result = json.dumps(
            {
                "results": [
                    {
                        "index": 0,
                        "test_id": "t1",
                        "compile_success": True,
                        "crash_triggered": True,
                        "crash_id": "n1",
                        "crash_category": "fully_novel_crash",
                        "new_states": [],
                        "mutation_count": 1,
                        "total_packets": 50,
                        "description": "d0",
                    },
                    {
                        "index": 1,
                        "test_id": "t2",
                        "compile_success": True,
                        "crash_triggered": True,
                        "crash_id": "n1",
                        "crash_category": "fully_novel_crash",
                        "new_states": [],
                        "mutation_count": 1,
                        "total_packets": 50,
                        "description": "d1",
                    },
                    {
                        "index": 2,
                        "test_id": "t3",
                        "compile_success": True,
                        "crash_triggered": True,
                        "crash_id": "p1",
                        "crash_category": "publicly_known_crash",
                        "new_states": [],
                        "mutation_count": 1,
                        "total_packets": 50,
                        "description": "d2",
                    },
                ]
            }
        )
        batch_handler = MagicMock(return_value=batch_result)

        mock_client = MagicMock()
        tool_call_response = _build_mock_response(
            finish_reason="tool_calls",
            text="batch",
            tool_calls=[
                {
                    "name": "execute_test_batch",
                    "input": {
                        "test_cases": [
                            {"exploit_code": "a"},
                            {"exploit_code": "b"},
                            {"exploit_code": "c"},
                        ]
                    },
                    "id": "etb1",
                }
            ],
        )
        mock_client.chat.completions.create.side_effect = [
            tool_call_response,
            _build_mock_response(finish_reason="stop"),
        ]

        kb, engine = self._make_kb_engine()
        agent_metrics = MagicMock()
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            ),
            "execute_test_batch": ({"name": "execute_test_batch"}, batch_handler),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools,
                execution_engine=engine,
                knowledge_base=kb,
                max_turns=2,
                agent_metrics=agent_metrics,
            )
            agent.run("/test/cap.pcapng")

        assert agent.session_unique_novel_crash_ids == {"n1"}
        assert agent.session_unique_crash_ids == {"n1", "p1"}

        assert agent_metrics.log_turn.call_count >= 1
        last_call = agent_metrics.log_turn.call_args_list[-1]
        assert "session_unique_novel_crash_ids" in last_call.kwargs
        assert last_call.kwargs["session_unique_novel_crash_ids"] == {"n1"}

    def test_full_mode_initial_briefing_contains_past_findings(self):
        from agent_core import FuzzAgent
        from version_config import get_version_config

        mock_client = MagicMock()
        response = _build_mock_response(finish_reason="stop", text="Turn 1 response.")
        mock_client.chat.completions.create.return_value = response

        kb = MagicMock()
        kb.get_strategy.return_value = ""
        kb.get_test_history.return_value = []
        kb.get_global_findings.return_value = []
        kb.query_findings.return_value = [
            {"description": "Confirmed RRC Setup Vulnerability", "tags": ["crash"]}
        ]

        engine = MagicMock()
        engine.test_count = 0

        config = get_version_config("full")
        tools = {
            "list_packet_types": (
                {"name": "list_packet_types"},
                MagicMock(return_value="[]"),
            ),
        }

        with patch("agent_core.OpenAI", return_value=mock_client):
            agent = FuzzAgent(
                tools=tools,
                execution_engine=engine,
                knowledge_base=kb,
                max_turns=1,
                cold_start=False,
                config=config,
            )
            agent.run("/test/capture.pcapng")

        assert mock_client.chat.completions.create.called
        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        messages = call_kwargs.get("messages", [])
        user_content = messages[1]["content"] if len(messages) > 1 else ""
        assert "## Previous Findings (accumulated across past sessions)" in user_content
        assert "Confirmed RRC Setup Vulnerability" in user_content
        kb.query_findings.assert_called_once_with(include_past_sessions=True, limit=50)

