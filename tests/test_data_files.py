"""Test that all local data files (captures, glossary, template) exist and are valid."""

import json
import os


class TestCaptureFiles:
    def test_normal_capture_exists(self, normal_capture):
        assert os.path.isfile(normal_capture), (
            f"Normal capture not found: {normal_capture}"
        )

    def test_normal_capture_not_empty(self, normal_capture):
        assert os.path.getsize(normal_capture) > 1000, (
            "Normal capture is suspiciously small"
        )

    def test_normal_capture_is_pcapng(self, normal_capture):
        with open(normal_capture, "rb") as f:
            magic = f.read(4)
        # pcapng section header block magic
        assert magic == b"\x0a\x0d\x0d\x0a", f"Not a pcapng file: magic={magic.hex()}"

    def test_fuzz_capture_exists(self, fuzz_capture):
        assert os.path.isfile(fuzz_capture), f"Fuzz capture not found: {fuzz_capture}"

    def test_fuzz_capture_not_empty(self, fuzz_capture):
        assert os.path.getsize(fuzz_capture) > 1000


class TestGlossary:
    def test_glossary_exists(self, agent_path):
        path = os.path.join(agent_path, "data/glossary/fiveg_fields_desc.json")
        assert os.path.isfile(path)

    def test_glossary_is_valid_json(self, agent_path):
        path = os.path.join(agent_path, "data/glossary/fiveg_fields_desc.json")
        with open(path, "r") as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert len(data) > 100, f"Glossary only has {len(data)} entries"

    def test_glossary_has_key_fields(self, agent_path):
        path = os.path.join(agent_path, "data/glossary/fiveg_fields_desc.json")
        with open(path, "r") as f:
            data = json.load(f)
        for field in ["nr-rrc.c1", "mac-nr.rnti", "nas_5gs.mm.message_type"]:
            assert field in data, f"Missing key field: {field}"


class TestExploitTemplate:
    def test_template_exists(self, agent_path):
        path = os.path.join(agent_path, "data/exploit.template")
        assert os.path.isfile(path)

    def test_template_has_placeholders(self, agent_path):
        path = os.path.join(agent_path, "data/exploit.template")
        with open(path, "r") as f:
            content = f.read()
        for placeholder in [
            "$wd_filters_declaration",
            "$wd_filters_setup",
            "$wd_filter_registration",
            "$wd_filter_action",
        ]:
            assert placeholder in content, f"Missing placeholder: {placeholder}"

    def test_template_has_required_functions(self, agent_path):
        path = os.path.join(agent_path, "data/exploit.template")
        with open(path, "r") as f:
            content = f.read()
        for func in ["module_name", "setup", "tx_pre_dissection", "tx_post_dissection"]:
            assert func in content, f"Missing function: {func}"


class TestDirectories:
    def test_logs_dir_exists(self, agent_path):
        assert os.path.isdir(os.path.join(agent_path, "logs"))

    # def test_logs_5gnr_gnb_dir_exists(self, agent_path):
    # assert os.path.isdir(os.path.join(agent_path, "logs/5gnr_gnb"))

    def test_kb_dir_exists(self, agent_path):
        assert os.path.isdir(os.path.join(agent_path, "kb"))

    def test_exploit_folder_exists(self, wdissector_path):
        path = os.path.join(wdissector_path, "modules/exploits/5gnr_gnb")
        assert os.path.isdir(path)
