import json
import logging
import time
from datetime import datetime

from openai import APIError, OpenAI, RateLimitError

from constants import (
    BATCH_TOOL_RESULT_MAX_CHARS,
    CRASH_FULLY_NOVEL,
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_PROVIDER,
    MAX_TOKENS,
    MODEL,
    SUMMARIZE_THRESHOLD_DEFAULT,
    SUMMARIZE_THRESHOLD_LARGE,
)
from prompts.system import (
    build_cold_start_prompt,
    build_initial_briefing,
    build_known_crashes_briefing,
    build_research_prompt,
    build_system_prompt,
)
from version_config import FuzzerVersion, VersionConfig

logger = logging.getLogger(__name__)
runtime_logger = logging.getLogger("runtime")


class FuzzAgent:
    def __init__(
        self,
        tools: dict,
        execution_engine,
        knowledge_base,
        max_turns: int = 0,
        cold_start: bool = False,
        target_vendor: str = "MediaTek",
        target_protocol: str = "5G NR",
        model_override: str | None = None,
        resource_monitor=None,
        agent_metrics=None,
        config: VersionConfig | None = None,
        profile=None,
    ):
        self.client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)
        self.model = model_override or MODEL
        logger.info(
            f"LLM backend ({LLM_PROVIDER}): {LLM_BASE_URL} | model: {self.model}"
        )
        self.tools = tools
        self.engine = execution_engine
        self.kb = knowledge_base
        self.max_turns = max_turns  # 0 = unlimited
        self.cold_start = cold_start
        self.target_vendor = target_vendor
        self.target_protocol = target_protocol
        self.profile = profile
        self.messages: list[dict] = []
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.consecutive_failures = 0
        self.session_unique_crash_ids: set[str] = set()
        self.session_unique_novel_crash_ids: set[str] = set()
        self.first_crash_confirmed: bool = False
        self.first_crash_test_count: int | None = None
        self.first_crash_timestamp: float | None = None
        self.REFLECTION_THRESHOLD = 5
        self.resource_monitor = resource_monitor
        self.agent_metrics = agent_metrics
        if config is None:
            from version_config import get_version_config

            config = get_version_config("full")
        self.config = config

    def _get_tool_schemas(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": schema["name"],
                    "description": schema.get("description", ""),
                    "parameters": schema.get("input_schema", {}),
                },
            }
            for schema, _ in self.tools.values()
        ]

    # Max chars in a tool result sent back to the model (~4k tokens)
    TOOL_RESULT_MAX_CHARS = 16_000
    MAX_CONSECUTIVE_API_ERRORS = 10
    MAX_EMPTY_RETRIES = 5

    def _handle_tool_call(self, tool_name: str, tool_input: dict) -> str:
        if tool_name not in self.tools:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        _, handler = self.tools[tool_name]
        try:
            result = handler(tool_input)
            # Note: execute_test results are logged to KB in the main loop
            # Truncate oversized results to stay within token budget
            max_chars = (
                BATCH_TOOL_RESULT_MAX_CHARS
                if tool_name == "execute_test_batch"
                else self.TOOL_RESULT_MAX_CHARS
            )
            if len(result) > max_chars:
                truncated = result[:max_chars]
                result = (
                    truncated
                    + f"\n... [TRUNCATED — {len(result)} chars total, showing first {max_chars}]"
                )
                logger.warning(
                    f"Tool {tool_name} result truncated from {len(result)} chars"
                )
            return result
        except Exception as e:
            logger.error(f"Tool {tool_name} error: {e}", exc_info=True)
            return json.dumps({"error": str(e)})

    def _estimate_tokens(self) -> int:
        """Rough estimate of conversation token count."""
        total_chars = 0
        for msg in self.messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        total_chars += len(json.dumps(block))
            # Count tool_calls arguments in assistant messages
            if "tool_calls" in msg:
                for tc in msg["tool_calls"]:
                    if isinstance(tc, dict):
                        total_chars += len(tc.get("function", {}).get("arguments", ""))
        return total_chars // 4  # rough char-to-token ratio

    def _summarize_if_needed(self):
        """Summarize old messages if approaching context limits.

        Preserves structured test results, findings, and key reasoning
        instead of naive truncation.
        """
        estimated_tokens = self._estimate_tokens()
        threshold = (
            SUMMARIZE_THRESHOLD_LARGE
            if self.config.version in (FuzzerVersion.V3, FuzzerVersion.V3F, FuzzerVersion.FULL)
            else SUMMARIZE_THRESHOLD_DEFAULT
        )
        if estimated_tokens < threshold:
            return

        logger.info(f"Context at ~{estimated_tokens} tokens, summarizing...")
        runtime_logger.info(
            f"[CONTEXT] Summarizing conversation at ~{estimated_tokens} tokens ({len(self.messages)} messages)"
        )

        # Keep last 6 messages (3 turns) to preserve recent test-analyze-record cycle
        if len(self.messages) <= 8:
            return

        split_idx = len(self.messages) - 6

        # Walk split backward if it lands between an assistant (tool_calls) and its tool results.
        # Tool results must always have their parent assistant message in the same segment.
        while split_idx > 0 and self.messages[split_idx]["role"] == "tool":
            split_idx -= 1

        old_messages = self.messages[:split_idx]
        recent_messages = self.messages[split_idx:]

        # Extract structured information from old messages
        test_results = []
        findings = []
        key_reasoning = []

        for msg in old_messages:
            content = msg.get("content", "")
            role = msg["role"]

            # Extract from tool results (tool role messages)
            if role == "tool":
                block_content = str(content)
                if (
                    '"test_id"' in block_content
                    and '"crash_triggered"' in block_content
                ):
                    try:
                        data = json.loads(block_content)
                        test_results.append(
                            f"Test {data.get('test_id')}: {data.get('fuzz_description', data.get('description', ''))[:80]} | "
                            f"crash={data.get('crash_triggered', False)} | "
                            f"mutations={data.get('mutation_count', '?')} | "
                            f"packets={data.get('total_packets', '?')} | "
                            f"new_states={len(data.get('new_states', []))}"
                        )
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass
                if '"finding_id"' in block_content:
                    try:
                        data = json.loads(block_content)
                        findings.append(
                            f"Finding {data.get('finding_id')}: {data.get('description', '')[:150]}"
                        )
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass

            # Also extract from legacy list-content user messages (pre-migration history)
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    block_content = str(block.get("content", ""))

                    # Parse execute_test results
                    if (
                        '"test_id"' in block_content
                        and '"crash_triggered"' in block_content
                    ):
                        try:
                            data = json.loads(block_content)
                            test_results.append(
                                f"Test {data.get('test_id')}: {data.get('fuzz_description', data.get('description', ''))[:80]} | "
                                f"crash={data.get('crash_triggered', False)} | "
                                f"mutations={data.get('mutation_count', '?')} | "
                                f"packets={data.get('total_packets', '?')} | "
                                f"new_states={len(data.get('new_states', []))}"
                            )
                        except (json.JSONDecodeError, TypeError, AttributeError):
                            pass

                    # Parse save_finding results
                    if '"finding_id"' in block_content:
                        try:
                            data = json.loads(block_content)
                            findings.append(
                                f"Finding {data.get('finding_id')}: {data.get('description', '')[:150]}"
                            )
                        except (json.JSONDecodeError, TypeError, AttributeError):
                            pass

            # Extract key reasoning from assistant text
            if role == "assistant":
                text = content if isinstance(content, str) else ""
                if text:
                    for sentence in text.split(". "):
                        sentence_lower = sentence.lower()
                        if any(
                            kw in sentence_lower
                            for kw in [
                                "hypothesis",
                                "because",
                                "suggest",
                                "interest",
                                "approach",
                                "insight",
                                "crash",
                                "learn",
                                "strateg",
                                "conclusion",
                                "important",
                                "discover",
                            ]
                        ):
                            cleaned = sentence.strip()[:200]
                            if len(cleaned) > 30:
                                key_reasoning.append(cleaned)

        # Build structured summary
        parts = ["## Conversation Summary (older turns condensed)"]

        if test_results:
            parts.append("\n### Test Results")
            for tr in test_results:
                parts.append(f"- {tr}")

        if findings:
            parts.append("\n### Key Findings Recorded")
            for f in findings:
                parts.append(f"- {f}")

        if key_reasoning:
            parts.append("\n### Agent Reasoning Highlights")
            # Deduplicate and keep most recent
            seen = set()
            unique = []
            for r in reversed(key_reasoning):
                key = r[:50].lower()
                if key not in seen:
                    seen.add(key)
                    unique.append(r)
            for r in reversed(unique[:10]):
                parts.append(f"- {r}")

        parts.append(
            "\n(Full findings and test history are preserved in the knowledge base. Use get_test_history and query_findings to access them.)"
        )

        summary = "\n".join(parts)

        self.messages = [{"role": "user", "content": summary}] + recent_messages
        self._fix_message_order()
        new_tokens = self._estimate_tokens()
        logger.info(f"Summarized to ~{new_tokens} tokens")
        runtime_logger.info(
            f"[CONTEXT] Summarized: {len(old_messages)} old msgs -> structured summary. Now ~{new_tokens} tokens"
        )

    def _fix_message_order(self):
        """Ensure messages alternate user/assistant properly.

        Tool messages (role="tool") follow assistant messages and are
        valid in the OpenAI format, so they skip alternation checks.
        """
        if not self.messages:
            return
        fixed = []
        last_role = None
        for msg in self.messages:
            role = msg["role"]
            if role == "tool":
                # Tool results always follow assistant, no alternation issue
                fixed.append(msg)
                continue
            if role == last_role:
                # Merge or skip
                if role == "user" and fixed:
                    prev_content = fixed[-1].get("content", "")
                    curr_content = msg.get("content", "")
                    if isinstance(prev_content, str) and isinstance(curr_content, str):
                        fixed[-1]["content"] = prev_content + "\n" + curr_content
                        continue
                # Insert a minimal turn
                filler_role = "assistant" if role == "user" else "user"
                fixed.append({"role": filler_role, "content": "(continuing)"})
            fixed.append(msg)
            last_role = role
        self.messages = fixed

    def _add_session_crash(self, crash_id: str, category: str) -> None:
        """Compare and add a crash_id to session unique lists using custom protocol equivalence."""
        if not crash_id:
            return

        # Safely extract equivalence comparison method from self.engine.td_utils
        td_utils = getattr(self.engine, "td_utils", None)
        are_equivalent = getattr(
            td_utils, "are_crashes_equivalent", lambda a, b: a == b
        )

        # Check and insert into general unique crashes set
        is_dup = False
        for existing in self.session_unique_crash_ids:
            res = are_equivalent(existing, crash_id)
            if not isinstance(res, bool):
                res = existing == crash_id
            if res:
                is_dup = True
                break
        if not is_dup:
            self.session_unique_crash_ids.add(crash_id)

        # Check and insert into novel unique crashes set
        if category == CRASH_FULLY_NOVEL:
            is_novel_dup = False
            for existing in self.session_unique_novel_crash_ids:
                res = are_equivalent(existing, crash_id)
                if not isinstance(res, bool):
                    res = existing == crash_id
                if res:
                    is_novel_dup = True
                    break
            if not is_novel_dup:
                self.session_unique_novel_crash_ids.add(crash_id)

    def _log_error_turn(
        self, turn: int, error: str, input_tokens: int = 0, output_tokens: int = 0
    ):
        """Record a stub metrics row for a turn that bailed on an error path
        (rate limit, API/LLM error, empty response) before reaching the normal
        log_turn() call. Without this, the turn counter advances but no row is
        written, so the dashboard's total_turns (= row count) under-reports the
        turns actually attempted. Cumulative counters carry forward unchanged
        (zero deltas); the row is tagged phase="error" and an error reason."""
        if not self.agent_metrics:
            return
        self.agent_metrics.log_turn(
            turn=turn,
            tools_called=[],
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cumulative_input_tokens=self.total_input_tokens,
            cumulative_output_tokens=self.total_output_tokens,
            turn_crashes=0,
            turn_publicly_known=0,
            turn_non_publicly_known=0,
            turn_fully_novel=0,
            session_unique_crash_ids=self.session_unique_crash_ids,
            session_unique_novel_crash_ids=self.session_unique_novel_crash_ids,
            phase="error",
            cumulative_test_count=self.engine.test_count,
            first_crash_test_count=self.first_crash_test_count,
            first_crash_timestamp=self.first_crash_timestamp,
            error=error,
        )

    def run(self, base_capture_path: str):
        """Main agent loop."""
        logger.info("Starting FuzzAgent...")
        self.base_capture_path = base_capture_path

        # Get initial packet type summary
        _, list_packet_types_handler = self.tools["list_packet_types"]
        packet_summary = list_packet_types_handler({"capture_path": base_capture_path})

        # Build initial messages
        strategy = self.kb.get_strategy()
        system_prompt = build_system_prompt(
            strategy,
            config=self.config,
            capture_path=base_capture_path,
            post_first_crash=self.first_crash_confirmed,
            profile=self.profile,
        )
        initial_briefing = build_initial_briefing(
            packet_summary, capture_path=base_capture_path, profile=self.profile
        )

        if self.cold_start and self.config.version == FuzzerVersion.FULL:
            # Cold start: zero prior knowledge — agent must bootstrap from web research
            logger.info(
                "COLD START mode: no known crashes, no global KB, no session history loaded"
            )
            protocol = self.profile.protocol if self.profile else "fiveg"
            initial_briefing += "\n" + build_cold_start_prompt(
                self.target_vendor,
                protocol=protocol,
            )
        elif self.config.version == FuzzerVersion.FULL:
            # FULL mode: load known crashes + global KB + session history
            known_crashes_briefing = build_known_crashes_briefing(
                known_crashes_path=self.profile.known_crashes_path
                if self.profile
                else None
            )
            if known_crashes_briefing:
                initial_briefing += "\n" + known_crashes_briefing

            # Load global KB findings
            global_findings = self.kb.get_global_findings(limit=30)
            if global_findings:
                gf_str = json.dumps(global_findings, indent=2)
                initial_briefing += f"\n\n## Global Knowledge Base (accumulated across all runs)\n```json\n{gf_str}\n```"

            # Add test history if resuming
            test_history = self.kb.get_test_history(limit=20)
            if test_history:
                if any(t.get("crash") and t.get("crash_id") for t in test_history):
                    self.first_crash_confirmed = True
                history_str = json.dumps(test_history, indent=2)
                initial_briefing += f"\n\n## Previous Test History (resuming session)\n```json\n{history_str}\n```"

            # Load accumulated findings across past session directories under KB_PATH
            findings = self.kb.query_findings(include_past_sessions=True, limit=50)
            if findings:
                findings_str = json.dumps(findings, indent=2)
                initial_briefing += f"\n\n## Previous Findings (accumulated across past sessions)\n```json\n{findings_str}\n```"
        else:
            # V1/V2/V3: no prior knowledge loaded, add research prompt if applicable
            logger.info(
                f"Version {self.config.version.value}: no prior crash knowledge loaded"
            )
            protocol = self.profile.protocol if self.profile else "fiveg"
            research_prompt = build_research_prompt(
                self.config,
                self.target_vendor,
                protocol=protocol,
                profile=self.profile,
            )
            if research_prompt:
                initial_briefing += "\n" + research_prompt

        self.messages = [{"role": "user", "content": initial_briefing}]

        turn = 0
        consecutive_api_errors = 0
        empty_response_retries = 0
        while True:
            turn += 1
            turn_tools_called = []
            turn_crashes = 0
            turn_publicly_known = 0
            turn_non_publicly_known = 0
            turn_fully_novel = 0
            turn_input_tokens = 0
            turn_output_tokens = 0

            if self.resource_monitor:
                self.resource_monitor.set_turn(turn)

            if self.max_turns > 0 and turn > self.max_turns:
                logger.info(f"Reached max_turns limit ({self.max_turns}). Stopping.")
                runtime_logger.info(f"[STOP] max_turns={self.max_turns} reached")
                break

            # Rebuild system prompt each turn (includes latest strategy)
            strategy = self.kb.get_strategy()
            system_prompt = build_system_prompt(
                strategy,
                config=self.config,
                capture_path=self.base_capture_path,
                profile=self.profile,
                post_first_crash=self.first_crash_confirmed,
            )

            # Summarize if needed
            self._summarize_if_needed()

            logger.info(
                f"--- Turn {turn} | ~{self._estimate_tokens()} tokens | Tests: {self.engine.test_count} ---"
            )
            runtime_logger.info("=" * 80)
            runtime_logger.info(
                f"TURN {turn} | {datetime.now().isoformat()} | ~{self._estimate_tokens()} tokens | Tests: {self.engine.test_count}"
            )
            runtime_logger.info("=" * 80)

            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_completion_tokens=MAX_TOKENS,
                    tools=self._get_tool_schemas(),
                    messages=[{"role": "system", "content": system_prompt}]
                    + self.messages,
                )
            except RateLimitError as e:
                # Parse retry-after from headers if available
                retry_after = 60
                if hasattr(e, "response") and e.response is not None:
                    retry_header = e.response.headers.get("retry-after")
                    if retry_header:
                        try:
                            retry_after = int(retry_header) + 5  # add buffer
                        except ValueError:
                            pass
                retry_after = min(retry_after, 300)  # Cap at 5 minutes
                consecutive_api_errors += 1
                logger.warning(
                    f"Rate limited (429). Waiting {retry_after}s before retry... ({consecutive_api_errors}/{self.MAX_CONSECUTIVE_API_ERRORS})"
                )
                runtime_logger.warning(
                    f"[RATE LIMIT] 429 hit. Backing off {retry_after}s"
                )
                if consecutive_api_errors >= self.MAX_CONSECUTIVE_API_ERRORS:
                    logger.critical(
                        f"Aborting: {consecutive_api_errors} consecutive API errors"
                    )
                    runtime_logger.critical(
                        f"[ABORT] {consecutive_api_errors} consecutive API failures"
                    )
                    self._log_error_turn(turn, "rate_limit")
                    break
                self._log_error_turn(turn, "rate_limit")
                time.sleep(retry_after)
                continue
            except APIError as e:
                consecutive_api_errors += 1
                logger.error(
                    f"API error: {e} ({consecutive_api_errors}/{self.MAX_CONSECUTIVE_API_ERRORS})"
                )
                runtime_logger.error(f"[API ERROR] {e}")
                if consecutive_api_errors >= self.MAX_CONSECUTIVE_API_ERRORS:
                    logger.critical(
                        f"Aborting: {consecutive_api_errors} consecutive API errors"
                    )
                    runtime_logger.critical(
                        f"[ABORT] {consecutive_api_errors} consecutive API failures"
                    )
                    self._log_error_turn(turn, "api_error")
                    break
                self._log_error_turn(turn, "api_error")
                time.sleep(min(15 * consecutive_api_errors, 120))
                continue
            except Exception as e:
                logger.error(
                    f"Unexpected LLM error: {type(e).__name__}: {e}", exc_info=True
                )
                runtime_logger.error(f"[LLM ERROR] {type(e).__name__}: {e}")
                consecutive_api_errors += 1
                if consecutive_api_errors >= self.MAX_CONSECUTIVE_API_ERRORS:
                    logger.critical(
                        f"Aborting: {consecutive_api_errors} consecutive API errors"
                    )
                    runtime_logger.critical(
                        f"[ABORT] {consecutive_api_errors} consecutive API failures"
                    )
                    self._log_error_turn(turn, "llm_error")
                    break
                self._log_error_turn(turn, "llm_error")
                time.sleep(min(15 * consecutive_api_errors, 120))
                continue

            if response is None or not getattr(response, "choices", None):
                logger.error("LLM returned None or empty choices, retrying...")
                runtime_logger.error("[LLM ERROR] Response is None or has no choices")
                consecutive_api_errors += 1
                if consecutive_api_errors >= self.MAX_CONSECUTIVE_API_ERRORS:
                    logger.critical(
                        f"Aborting: {consecutive_api_errors} consecutive empty responses"
                    )
                    runtime_logger.critical(
                        f"[ABORT] {consecutive_api_errors} consecutive empty responses"
                    )
                    self._log_error_turn(turn, "empty_response")
                    break
                self._log_error_turn(turn, "empty_response")
                time.sleep(10)
                continue

            consecutive_api_errors = 0
            message = response.choices[0].message
            finish_reason = response.choices[0].finish_reason

            if response.usage is not None:
                turn_input_tokens = response.usage.prompt_tokens
                turn_output_tokens = response.usage.completion_tokens
                self.total_input_tokens += turn_input_tokens
                self.total_output_tokens += turn_output_tokens
                logger.info(
                    f"Stop reason: {finish_reason} | "
                    f"In: {response.usage.prompt_tokens}, Out: {response.usage.completion_tokens} | "
                    f"Total in: {self.total_input_tokens}, Total out: {self.total_output_tokens}"
                )
                runtime_logger.info(
                    f"[API] stop={finish_reason} | tokens in={response.usage.prompt_tokens} out={response.usage.completion_tokens} | cumulative in={self.total_input_tokens} out={self.total_output_tokens}"
                )
            else:
                logger.info(f"Stop reason: {finish_reason} | Usage data not available")
                runtime_logger.info(f"[API] stop={finish_reason} | usage=N/A")

            # Process response
            if message.content is None and not message.tool_calls:
                empty_response_retries += 1
                logger.warning(
                    f"API returned empty content, retrying... ({empty_response_retries}/{self.MAX_EMPTY_RETRIES})"
                )
                runtime_logger.warning(
                    f"[API] Empty content received, retrying ({empty_response_retries}/{self.MAX_EMPTY_RETRIES})"
                )
                if empty_response_retries >= self.MAX_EMPTY_RETRIES:
                    logger.error("Max empty response retries reached, breaking")
                    runtime_logger.error("[ABORT] Max empty response retries reached")
                    self._log_error_turn(
                        turn, "empty_content", turn_input_tokens, turn_output_tokens
                    )
                    break
                self._log_error_turn(
                    turn, "empty_content", turn_input_tokens, turn_output_tokens
                )
                time.sleep(5)
                continue

            empty_response_retries = 0

            # Build assistant message for history
            assistant_msg = {"role": "assistant", "content": message.content or ""}
            if message.tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in message.tool_calls
                ]

            self.messages.append(assistant_msg)

            if message.content:
                logger.info(f"Agent: {message.content}")
                runtime_logger.info(f"[REASONING]\n{message.content}")

            # Handle tool calls
            if message.tool_calls:
                tool_results = []
                first_crash_just_confirmed = False
                for tc in message.tool_calls:
                    tool_name = tc.function.name
                    try:
                        tool_input = json.loads(tc.function.arguments)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Malformed JSON in tool call {tool_name}: {e}. Raw: {tc.function.arguments[:500]}"
                        )
                        runtime_logger.warning(
                            f"[TOOL CALL ERROR] {tool_name}: malformed arguments JSON: {e}"
                        )
                        tool_results.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc.id,
                                "content": f"Error: your tool call had malformed JSON arguments: {e}. Please retry with valid JSON.",
                            }
                        )
                        continue
                    logger.info(
                        f"Tool call: {tool_name}({json.dumps(tool_input)[:200]})"
                    )
                    runtime_logger.info(f"[TOOL CALL] {tool_name}")
                    runtime_logger.info(
                        f"[TOOL INPUT]\n{json.dumps(tool_input, indent=2)}"
                    )

                    if tool_name == "execute_test" and self.resource_monitor:
                        self.resource_monitor.mark_event(
                            "test_start",
                            {
                                "test_id": f"{self.engine.run_id}-{self.engine.test_count + 1}"
                            },
                        )
                    if tool_name == "execute_test_batch" and self.resource_monitor:
                        self.resource_monitor.mark_event(
                            "batch_start",
                            {
                                "run_id": self.engine.run_id,
                                "batch_size": len(tool_input.get("test_cases", [])),
                            },
                        )

                    start = time.time()
                    result = self._handle_tool_call(tool_name, tool_input)
                    elapsed = time.time() - start
                    turn_tools_called.append(tool_name)

                    if tool_name == "execute_test" and self.resource_monitor:
                        self.resource_monitor.mark_event(
                            "test_end",
                            {
                                "test_id": f"{self.engine.run_id}-{self.engine.test_count}"
                            },
                        )
                    if tool_name == "execute_test_batch" and self.resource_monitor:
                        self.resource_monitor.mark_event(
                            "batch_end", {"run_id": self.engine.run_id}
                        )

                    logger.info(
                        f"Tool {tool_name} took {elapsed:.1f}s, result: {result[:300]}..."
                    )
                    runtime_logger.info(
                        f"[TOOL RESULT] {tool_name} ({elapsed:.1f}s)\n{result}"
                    )

                    # Log test to KB if execute_test
                    if tool_name == "execute_test":
                        try:
                            result_data = json.loads(result)
                            from execution_engine import TestResult

                            exploit_prefix = (
                                self.profile.exploit_prefix
                                if self.profile
                                else "mac_sch_"
                            )
                            default_exploit_name = (
                                f"{exploit_prefix}laf"
                                if exploit_prefix
                                else "exploit_laf"
                            )
                            tr = TestResult(
                                test_id=result_data.get("test_id", ""),
                                fuzz_description=tool_input.get("description", ""),
                                compile_success=result_data.get(
                                    "compile_success", False
                                ),
                                compile_error=result_data.get("compile_error"),
                                execution_time_seconds=result_data.get(
                                    "execution_time_seconds", 0
                                ),
                                crash_triggered=result_data.get(
                                    "crash_triggered", False
                                ),
                                crash_id=result_data.get("crash_id"),
                                crash_category=result_data.get("crash_category", ""),
                                crash_summary=result_data.get("crash_summary"),
                                exploit_name=tool_input.get(
                                    "exploit_name", default_exploit_name
                                ),
                                exploit_code=tool_input.get("exploit_code", ""),
                                new_states=result_data.get("new_states", []),
                                new_transitions=result_data.get("new_transitions", []),
                                capture_path=result_data.get("capture_path", ""),
                                log_path=result_data.get("log_path", ""),
                                total_packets=result_data.get("total_packets", 0),
                                exploit_hash="",
                                mutation_count=result_data.get("mutation_count", 0),
                            )
                            self.kb.log_test(tr, tool_input.get("description", ""))
                            if result_data.get("crash_triggered"):
                                turn_crashes += 1
                                category = result_data.get("crash_category", "")
                                if category == "publicly_known_crash":
                                    turn_publicly_known += 1
                                elif category == "non_publicly_known_crash":
                                    turn_non_publicly_known += 1
                                elif category == "fully_novel_crash":
                                    turn_fully_novel += 1
                                crash_id = result_data.get("crash_id")
                                if crash_id:
                                    self._add_session_crash(crash_id, category)
                                    if not self.first_crash_confirmed:
                                        self.first_crash_confirmed = True
                                        first_crash_just_confirmed = True
                                        self.first_crash_test_count = (
                                            self.engine.test_count
                                        )
                                        self.first_crash_timestamp = time.time()
                        except Exception as e:
                            logger.error(f"Failed to log test to KB: {e}")

                    # Log batch tests to KB if execute_test_batch
                    if tool_name == "execute_test_batch":
                        try:
                            batch_data = json.loads(result)
                            from execution_engine import TestResult

                            for sub in batch_data.get("results", []):
                                idx = sub.get("index", 0)
                                tc_input = (
                                    tool_input.get("test_cases", [{}])[idx]
                                    if idx < len(tool_input.get("test_cases", []))
                                    else {}
                                )
                                tr = TestResult(
                                    test_id=sub.get("test_id", ""),
                                    fuzz_description=sub.get("description", ""),
                                    compile_success=sub.get("compile_success", False),
                                    compile_error=sub.get("compile_error"),
                                    execution_time_seconds=sub.get(
                                        "execution_time_seconds", 0
                                    ),
                                    crash_triggered=sub.get("crash_triggered", False),
                                    crash_id=sub.get("crash_id"),
                                    crash_category=sub.get("crash_category", ""),
                                    crash_summary=sub.get("crash_summary"),
                                    exploit_name=sub.get("exploit_name", ""),
                                    exploit_code=tc_input.get("exploit_code", ""),
                                    new_states=sub.get("new_states", []),
                                    new_transitions=sub.get("new_transitions", []),
                                    capture_path=sub.get("capture_path", ""),
                                    log_path=sub.get("log_path", ""),
                                    total_packets=sub.get("total_packets", 0),
                                    exploit_hash="",
                                    mutation_count=sub.get("mutation_count", 0),
                                )
                                self.kb.log_test(tr, sub.get("description", ""))
                                if sub.get("crash_triggered"):
                                    turn_crashes += 1
                                    category = sub.get("crash_category", "")
                                    if category == "publicly_known_crash":
                                        turn_publicly_known += 1
                                    elif category == "non_publicly_known_crash":
                                        turn_non_publicly_known += 1
                                    elif category == "fully_novel_crash":
                                        turn_fully_novel += 1
                                    crash_id = sub.get("crash_id")
                                    if crash_id:
                                        self._add_session_crash(crash_id, category)
                                        if not self.first_crash_confirmed:
                                            self.first_crash_confirmed = True
                                            first_crash_just_confirmed = True
                                            self.first_crash_test_count = (
                                                self.engine.test_count
                                            )
                                            self.first_crash_timestamp = time.time()
                        except Exception as e:
                            logger.error(f"Failed to log batch tests to KB: {e}")

                    # Track consecutive failures for reflection injection
                    if tool_name == "execute_test":
                        try:
                            rd = json.loads(result)
                            if (
                                rd.get("compile_success")
                                and not rd.get("crash_triggered")
                                and len(rd.get("new_states", [])) == 0
                            ):
                                self.consecutive_failures += 1
                            else:
                                self.consecutive_failures = 0
                        except Exception:
                            pass

                    if tool_name == "execute_test_batch":
                        try:
                            batch_data = json.loads(result)
                            for sub in batch_data.get("results", []):
                                if (
                                    sub.get("compile_success")
                                    and not sub.get("crash_triggered")
                                    and len(sub.get("new_states", [])) == 0
                                ):
                                    self.consecutive_failures += 1
                                else:
                                    self.consecutive_failures = 0
                        except Exception:
                            pass

                    tool_results.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": result,
                        }
                    )

                self.messages.extend(tool_results)

                # Inject post-first-crash directive when first crash is confirmed
                if first_crash_just_confirmed:
                    post_crash_msg = (
                        "FIRST CRASH CONFIRMED. You have proven you can trigger a crash. "
                        "From this point forward, your SOLE objective changes:\n\n"
                        "FOCUS EXCLUSIVELY on finding non_publicly_known_crash and fully_novel_crash crashes.\n\n"
                        "Stay close to what works — historical data shows nearly all novel crashes come from "
                        "variations on known vulnerable areas:\n"
                        "1. Try different values at confirmed crash offsets — values close to the original, "
                        "boundary values, and values producing different ASN.1 interpretations.\n"
                        "2. Explore adjacent offsets (±1 to ±6 bytes) and fill gaps between known crash zones.\n"
                        "3. Vary both bytes in multi-byte crashes to reach different crash components.\n"
                        "4. Zero individual bytes between known crash zones that have never been tested.\n"
                        "5. If a test produces a publicly_known_crash, try a different value at that same offset.\n"
                        "6. After each test, call save_finding + update_strategy in the same response — do not split across turns.\n"
                        "7. Update your strategy NOW to reflect this change in objective."
                    )
                    self.messages.append({"role": "user", "content": post_crash_msg})
                    runtime_logger.info(
                        "[POST-FIRST-CRASH] Injected novel crash hunting directive after first confirmed crash"
                    )

                # Inject reflection prompt after N consecutive fruitless tests
                if self.consecutive_failures >= self.REFLECTION_THRESHOLD:
                    n = self.consecutive_failures
                    reflection = (
                        f"REFLECTION REQUIRED: You have had {n} consecutive tests with no crashes and no new states. "
                        "Before your next test, you MUST:\n"
                        "1. Review your test history with get_test_history — check mutation_count for each test. Were mutations actually delivered?\n"
                        "2. Review which mutation categories you have tried. Are you stuck repeating the same approach (e.g. setting bytes to 0xFF)?\n"
                        "3. Identify under-explored categories from the mutation taxonomy (truncation, type_confusion, flooding, multi_stage, encoding_corruption).\n"
                        "4. Consider whether your filters are matching the right packets — use inspect_packets to verify.\n"
                        "5. Update your strategy with this analysis before running another test.\n"
                        "Do NOT run another execute_test until you have completed this reflection."
                    )
                    self.messages.append({"role": "user", "content": reflection})
                    runtime_logger.info(
                        f"[REFLECTION] Injected after {n} consecutive failures"
                    )
                    self.consecutive_failures = 0

            elif finish_reason == "stop":
                # Agent finished its thought, prompt for next action
                runtime_logger.info(
                    "[END TURN] Agent finished reasoning, prompting to continue"
                )
                self.messages.append(
                    {
                        "role": "user",
                        "content": "Continue with your next action. Design and execute your next test, or analyze previous results.",
                    }
                )

            else:
                logger.warning(f"Unexpected stop reason: {finish_reason}")
                self.messages.append(
                    {"role": "user", "content": "Continue with your next action."}
                )

            if self.agent_metrics:
                self.agent_metrics.log_turn(
                    turn=turn,
                    tools_called=turn_tools_called,
                    input_tokens=turn_input_tokens,
                    output_tokens=turn_output_tokens,
                    cumulative_input_tokens=self.total_input_tokens,
                    cumulative_output_tokens=self.total_output_tokens,
                    turn_crashes=turn_crashes,
                    turn_publicly_known=turn_publicly_known,
                    turn_non_publicly_known=turn_non_publicly_known,
                    turn_fully_novel=turn_fully_novel,
                    session_unique_crash_ids=self.session_unique_crash_ids,
                    session_unique_novel_crash_ids=self.session_unique_novel_crash_ids,
                    cumulative_test_count=self.engine.test_count,
                    first_crash_test_count=self.first_crash_test_count,
                    first_crash_timestamp=self.first_crash_timestamp,
                )
