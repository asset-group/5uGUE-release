"""Agent-level metrics — tools/turn, crash rate, token usage."""

import json
import logging
import os
import time
from collections import Counter

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)


class AgentMetrics:
    def __init__(self, run_id: str, log_dir: str):
        self._run_id = run_id
        self._log_path = os.path.join(log_dir, f"agent_metrics_{run_id}.jsonl")
        self._png_path = os.path.join(log_dir, f"agent_metrics_{run_id}.png")
        self._log_file = None
        self._records: list[dict] = []
        self._cumulative_crashes = 0
        self._cumulative_publicly_known = 0
        self._cumulative_non_publicly_known = 0
        self._cumulative_fully_novel = 0
        self._session_start_time: float | None = None

    @property
    def png_path(self) -> str:
        return self._png_path

    def start(self):
        """Open JSONL log file."""
        self._session_start_time = time.time()
        self._log_file = open(self._log_path, "a")
        logger.info(f"Agent metrics started: {self._log_path}")

    def log_turn(
        self,
        turn: int,
        tools_called: list[str],
        input_tokens: int,
        output_tokens: int,
        cumulative_input_tokens: int,
        cumulative_output_tokens: int,
        turn_crashes: int,
        turn_publicly_known: int,
        turn_non_publicly_known: int,
        turn_fully_novel: int,
        session_unique_crash_ids: set[str],
        session_unique_novel_crash_ids: set[str] = frozenset(),
        phase: str = "",
        cumulative_test_count: int = 0,
        first_crash_test_count: int | None = None,
        first_crash_timestamp: float | None = None,
        error: str | None = None,
    ):
        """Write one record per turn.

        ``error`` marks a stub record for a turn that bailed out on an error
        path (rate limit, API/LLM error, empty response) before completing
        normal work — see AgentLoop._log_error_turn. Stub records carry zero
        deltas so cumulative counters are unchanged, which keeps the turn
        visible/counted in the dashboard without distorting totals.
        """
        self._cumulative_crashes += turn_crashes
        self._cumulative_publicly_known += turn_publicly_known
        self._cumulative_non_publicly_known += turn_non_publicly_known
        self._cumulative_fully_novel += turn_fully_novel

        # Auto-detect phase from tool calls if not specified. Error stubs pass
        # phase="error" explicitly so they are not mislabelled as research.
        if not phase:
            test_tools = {"execute_test", "execute_test_batch", "submit_custom_exploit"}
            if any(t in test_tools for t in tools_called):
                phase = "testing"
            else:
                phase = "research"

        record = {
            "turn": turn,
            "timestamp": time.time(),
            "session_start_time": self._session_start_time,
            "tools_called": tools_called,
            "tool_call_count": len(tools_called),
            "tool_counts": dict(Counter(tools_called)),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cumulative_input_tokens": cumulative_input_tokens,
            "cumulative_output_tokens": cumulative_output_tokens,
            "turn_crashes": turn_crashes,
            "turn_publicly_known": turn_publicly_known,
            "turn_non_publicly_known": turn_non_publicly_known,
            "turn_fully_novel": turn_fully_novel,
            "cumulative_crashes": self._cumulative_crashes,
            "cumulative_publicly_known": self._cumulative_publicly_known,
            "cumulative_non_publicly_known": self._cumulative_non_publicly_known,
            "cumulative_fully_novel": self._cumulative_fully_novel,
            "session_unique_crashes": len(session_unique_crash_ids),
            "session_unique_novel_crashes": len(session_unique_novel_crash_ids),
            "cumulative_test_count": cumulative_test_count,
            "first_crash_test_count": first_crash_test_count,
            "first_crash_timestamp": first_crash_timestamp,
            "phase": phase,
            "error": error,
        }
        self._records.append(record)
        try:
            if self._log_file:
                self._log_file.write(json.dumps(record) + "\n")
                self._log_file.flush()
        except Exception as e:
            logger.warning(f"Failed to write agent metrics: {e}")

        try:
            from ingest_client import enqueue

            enqueue("turn", record, run_id=self._run_id)
        except Exception as e:
            logger.warning(f"ingest enqueue failed (turn): {e}")

    def stop(self):
        """Close file and generate chart."""
        if self._log_file:
            self._log_file.close()
            self._log_file = None
        self._generate_chart()

    def _generate_chart(self):
        if len(self._records) < 2:
            logger.warning("Not enough turns for agent metrics chart")
            return

        turns = [r["turn"] for r in self._records]
        tool_counts = [r["tool_call_count"] for r in self._records]
        cum_crashes = [r["cumulative_crashes"] for r in self._records]
        cum_publicly_known = [r["cumulative_publicly_known"] for r in self._records]
        cum_non_publicly_known = [
            r["cumulative_non_publicly_known"] for r in self._records
        ]
        cum_fully_novel = [r["cumulative_fully_novel"] for r in self._records]
        in_tokens = [r["input_tokens"] for r in self._records]
        out_tokens = [r["output_tokens"] for r in self._records]

        fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
        fig.suptitle(f"Agent Metrics — Run {self._run_id}", fontsize=13)

        # 1. Tools per turn
        ax = axes[0]
        if len(turns) > 40:
            ax.plot(turns, tool_counts, color="tab:blue", linewidth=1, marker=".")
        else:
            ax.bar(turns, tool_counts, color="tab:blue", alpha=0.8)
        ax.set_ylabel("Tool Calls")
        ax.set_title("Tool Calls per Turn")

        # 2. Cumulative crashes by category
        ax = axes[1]
        ax.plot(
            turns, cum_crashes, color="tab:red", linewidth=1.5, label="Total Crashes"
        )
        ax.plot(
            turns,
            cum_publicly_known,
            color="tab:blue",
            linewidth=1.5,
            linestyle="--",
            label="Publicly Known",
        )
        ax.plot(
            turns,
            cum_non_publicly_known,
            color="tab:orange",
            linewidth=1.5,
            linestyle="--",
            label="Non-Publicly Known",
        )
        ax.plot(
            turns,
            cum_fully_novel,
            color="tab:green",
            linewidth=1.5,
            linestyle=":",
            label="Fully Novel",
        )
        ax.set_ylabel("Crashes")
        ax.set_title("Cumulative Crashes")
        ax.legend(fontsize=8)

        # 3. Token usage per turn
        ax = axes[2]
        width = 0.35
        x_offset = [t - width / 2 for t in turns]
        x_offset2 = [t + width / 2 for t in turns]
        if len(turns) > 40:
            ax.plot(turns, in_tokens, color="tab:green", linewidth=1, label="Input")
            ax.plot(turns, out_tokens, color="tab:purple", linewidth=1, label="Output")
        else:
            ax.bar(
                x_offset, in_tokens, width, color="tab:green", alpha=0.8, label="Input"
            )
            ax.bar(
                x_offset2,
                out_tokens,
                width,
                color="tab:purple",
                alpha=0.8,
                label="Output",
            )
        ax.set_ylabel("Tokens")
        ax.set_xlabel("Turn")
        ax.set_title("Token Usage per Turn")
        ax.legend(fontsize=8)

        plt.tight_layout()
        fig.savefig(self._png_path, dpi=100, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"Agent metrics chart saved: {self._png_path}")
