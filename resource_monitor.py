"""Background resource monitor — samples CPU, memory, disk, and network every N seconds."""

import json
import logging
import os
import threading
import time

import psutil
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)


class ResourceMonitor:
    def __init__(self, run_id: str, log_dir: str, interval: float = 5.0):
        self._run_id = run_id
        self._log_path = os.path.join(log_dir, f"resources_{run_id}.jsonl")
        self._png_path = os.path.join(log_dir, f"resources_{run_id}.png")
        self._interval = interval
        self._current_turn = 0
        self._samples: list[dict] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._log_file = None
        self._process = psutil.Process()
        # Prime cpu_percent so first real call returns non-zero
        psutil.cpu_percent(interval=None)

    def start(self):
        """Open log file and start the daemon sampling thread."""
        self._log_file = open(self._log_path, "a")
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()
        logger.info(f"Resource monitor started: {self._log_path}")

    def stop(self):
        """Stop sampling, flush file, generate chart."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        if self._log_file:
            self._log_file.close()
            self._log_file = None
        self._generate_chart()

    def set_turn(self, turn: int):
        self._current_turn = turn

    def mark_event(self, event: str, metadata: dict | None = None):
        """Write an event-tagged sample (e.g. test_start, test_end)."""
        sample = self._take_sample()
        sample["event"] = event
        if metadata:
            sample["metadata"] = metadata
        self._write(sample)

    def _sample_loop(self):
        while not self._stop_event.is_set():
            try:
                sample = self._take_sample()
                self._write(sample)
            except Exception as e:
                logger.warning(f"Resource monitor sample error: {e}")
            self._stop_event.wait(self._interval)

    def _take_sample(self) -> dict:
        try:
            mem = self._process.memory_info()
            disk = psutil.disk_io_counters()
            net = psutil.net_io_counters()
            return {
                "ts": time.time(),
                "turn": self._current_turn,
                "cpu_percent": psutil.cpu_percent(interval=None),
                "mem_rss_mb": round(mem.rss / (1024 * 1024), 1),
                "mem_system_percent": psutil.virtual_memory().percent,
                "disk_read_mb": round(disk.read_bytes / (1024 * 1024), 1)
                if disk
                else 0,
                "disk_write_mb": round(disk.write_bytes / (1024 * 1024), 1)
                if disk
                else 0,
                "net_sent_mb": round(net.bytes_sent / (1024 * 1024), 1),
                "net_recv_mb": round(net.bytes_recv / (1024 * 1024), 1),
            }
        except Exception as e:
            logger.warning(f"Resource sample failed: {e}")
            return {"ts": time.time(), "turn": self._current_turn, "error": str(e)}

    def _write(self, sample: dict):
        self._samples.append(sample)
        if self._log_file:
            self._log_file.write(json.dumps(sample) + "\n")
            self._log_file.flush()
        try:
            from ingest_client import enqueue

            enqueue("resource", sample, run_id=self._run_id)
        except Exception as e:
            logger.warning(f"ingest enqueue failed (resource): {e}")

    def _generate_chart(self):
        if len(self._samples) < 2:
            logger.warning("Not enough samples for resource chart")
            return

        samples = self._samples
        t0 = samples[0]["ts"]
        elapsed = [(s["ts"] - t0) / 60.0 for s in samples]

        # Identify turn boundaries and events
        turn_times = []
        for i in range(1, len(samples)):
            if samples[i]["turn"] != samples[i - 1]["turn"]:
                turn_times.append(elapsed[i])

        test_start_times = [
            elapsed[i] for i, s in enumerate(samples) if s.get("event") == "test_start"
        ]
        test_end_times = [
            elapsed[i] for i, s in enumerate(samples) if s.get("event") == "test_end"
        ]

        # Compute I/O rates (MB/s) from cumulative counters
        def rates(key):
            r = [0.0]
            for i in range(1, len(samples)):
                dt = samples[i]["ts"] - samples[i - 1]["ts"]
                if dt > 0:
                    r.append((samples[i][key] - samples[i - 1][key]) / dt)
                else:
                    r.append(0.0)
            return r

        disk_read_rate = rates("disk_read_mb")
        disk_write_rate = rates("disk_write_mb")
        net_sent_rate = rates("net_sent_mb")
        net_recv_rate = rates("net_recv_mb")

        fig, axes = plt.subplots(2, 2, figsize=(14, 8), sharex=True)
        fig.suptitle(f"Resource Monitor — Run {self._run_id}", fontsize=13)

        def add_markers(ax):
            for t in turn_times:
                ax.axvline(t, color="gray", linestyle="--", alpha=0.3, linewidth=0.8)
            for t in test_start_times:
                ax.axvline(t, color="red", linestyle=":", alpha=0.5, linewidth=0.8)
            for t in test_end_times:
                ax.axvline(t, color="green", linestyle=":", alpha=0.5, linewidth=0.8)

        # Top-left: CPU
        ax = axes[0, 0]
        ax.plot(
            elapsed, [s["cpu_percent"] for s in samples], color="tab:blue", linewidth=1
        )
        ax.set_ylabel("CPU %")
        ax.set_ylim(0, 100)
        ax.set_title("CPU Usage")
        add_markers(ax)

        # Top-right: Memory
        ax = axes[0, 1]
        ax.plot(
            elapsed,
            [s["mem_rss_mb"] for s in samples],
            color="tab:orange",
            linewidth=1,
            label="RSS (MB)",
        )
        ax.set_ylabel("RSS (MB)")
        ax.set_title("Memory")
        ax2 = ax.twinx()
        ax2.plot(
            elapsed,
            [s["mem_system_percent"] for s in samples],
            color="tab:red",
            linewidth=1,
            alpha=0.6,
            label="System %",
        )
        ax2.set_ylabel("System %")
        ax2.set_ylim(0, 100)
        lines1, labels1 = ax.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax.legend(lines1 + lines2, labels1 + labels2, fontsize=8, loc="upper left")
        add_markers(ax)

        # Bottom-left: Disk I/O
        ax = axes[1, 0]
        ax.plot(elapsed, disk_read_rate, color="tab:green", linewidth=1, label="Read")
        ax.plot(
            elapsed, disk_write_rate, color="tab:purple", linewidth=1, label="Write"
        )
        ax.set_ylabel("MB/s")
        ax.set_xlabel("Elapsed (min)")
        ax.set_title("Disk I/O Rate")
        ax.legend(fontsize=8)
        add_markers(ax)

        # Bottom-right: Network I/O
        ax = axes[1, 1]
        ax.plot(elapsed, net_sent_rate, color="tab:cyan", linewidth=1, label="Sent")
        ax.plot(elapsed, net_recv_rate, color="tab:brown", linewidth=1, label="Recv")
        ax.set_ylabel("MB/s")
        ax.set_xlabel("Elapsed (min)")
        ax.set_title("Network I/O Rate")
        ax.legend(fontsize=8)
        add_markers(ax)

        plt.tight_layout()
        fig.savefig(self._png_path, dpi=100, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"Resource chart saved: {self._png_path}")
