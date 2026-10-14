import json
import os
import pytest

from dashboard.data_loader_files import load_sweep_data


class TestSweepDataLoaderFiles:
    def test_load_sweep_data_reads_device_and_protocol(self, tmp_path, monkeypatch):
        # Mock SWEEP_LOG_ROOT to point to our temp directory
        monkeypatch.setattr("dashboard.data_loader_files.SWEEP_LOG_ROOT", str(tmp_path))

        sweep_id = "sweep123"
        sweep_dir = tmp_path / sweep_id
        sweep_dir.mkdir()

        # Write fake results.jsonl and progress.jsonl files
        results_file = sweep_dir / "results.jsonl"
        results_file.write_text(
            '{"filter": "test-filter", "offset": 10, "value": 5, "crash": false, "compile_success": true}\n'
        )
        progress_file = sweep_dir / "progress.jsonl"
        progress_file.write_text('{"tests_completed": 1}\n')

        # Write manifest.json with device/protocol fields
        manifest = {
            "sweep_id": sweep_id,
            "device": "test-device",
            "protocol": "test-protocol",
            "profile": "quick",
            "filters": ["test-filter"],
            "offset_range": [0, 100],
            "offsets_per_filter": 10,
            "offset_strategy": "near_known",
            "values": [5],
            "results_path": str(results_file),
            "progress_path": str(progress_file),
            "total_combinations": 10,
        }
        manifest_file = sweep_dir / "manifest.json"
        with open(manifest_file, "w") as f:
            json.dump(manifest, f)

        data = load_sweep_data(sweep_id)
        assert data is not None
        assert data["manifest"]["device"] == "test-device"
        assert data["manifest"]["protocol"] == "test-protocol"
