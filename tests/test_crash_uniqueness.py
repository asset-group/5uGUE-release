"""Tests for crash classification against known crash signatures."""

import json
import os


class TestKnownCrashSignaturesFile:
    """Test data/known_crash_signatures.json integrity."""

    def test_file_exists(self, agent_path):
        path = os.path.join(agent_path, "data/known_crash_signatures.json")
        assert os.path.isfile(path)

    def test_valid_json_object(self, agent_path):
        path = os.path.join(agent_path, "data/known_crash_signatures.json")
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert "public" in data
        assert "non_public" in data
        assert isinstance(data["public"], list)
        assert isinstance(data["non_public"], list)
        assert len(data["public"]) > 0
        assert len(data["non_public"]) > 0

    def test_all_entries_are_strings(self, agent_path):
        path = os.path.join(agent_path, "data/known_crash_signatures.json")
        with open(path) as f:
            data = json.load(f)
        for sig in data["public"] + data["non_public"]:
            assert isinstance(sig, str)
            assert len(sig) > 10

    def test_no_overlap_between_public_and_non_public(self, agent_path):
        """Public and non_public lists must have no common strings."""
        path = os.path.join(agent_path, "data/known_crash_signatures.json")
        with open(path) as f:
            data = json.load(f)
        overlap = set(data["public"]) & set(data["non_public"])
        assert len(overlap) == 0, (
            f"Signatures appear in both public and non_public: {overlap}"
        )

    def test_constants_path(self):
        from constants import KNOWN_CRASH_SIGNATURES

        assert KNOWN_CRASH_SIGNATURES is not None
        assert "known_crash_signatures.json" in KNOWN_CRASH_SIGNATURES
        assert os.path.isfile(KNOWN_CRASH_SIGNATURES)


class TestClassifyCrash:
    """Test that classify_crash returns the correct category."""

    def test_public_signature_classified_correctly(self, td_utils):
        sig = "[ASSERT] file:dsp3/coresonic/msonic/modem/brp/nr/nr_brp/src/nr_brp_top_irq.c line:927"
        assert td_utils.classify_crash(sig) == "publicly_known_crash"

    def test_public_signature_with_prefix(self, td_utils):
        sig = "(MSONIC0) [ASSERT] file:dsp3/coresonic/msonic/modem/brp/nr/nr_brp/src/nr_brp_top_irq.c line:927"
        assert td_utils.classify_crash(sig) == "publicly_known_crash"

    def test_non_public_signature_classified_correctly(self, td_utils):
        sig = "[ASSERT] file:dsp3/coresonic/msonic/modem/tx/nr/tx/src/nr_tx_mngr.c line:2638"
        assert td_utils.classify_crash(sig) == "non_publicly_known_crash"

    def test_non_public_signature_with_suffix(self, td_utils):
        sig = "[Fatal error(MPU_NOT_ALLOW)] err_code1:0x0000001D err_code2:0x91082A14 err_code3:0x91082070 CaDeFa Supported extra_stuff"
        assert td_utils.classify_crash(sig) == "non_publicly_known_crash"

    def test_novel_crash_classified_correctly(self, td_utils):
        sig = "[ASSERT] file:completely/new/path.c line:99999 p1:0xDEADBEEF"
        assert td_utils.classify_crash(sig) == "fully_novel_crash"

    def test_novel_crash_idempotent(self, td_utils):
        """classify_crash is stateless — same result on repeated calls."""
        sig = "[ASSERT] file:brand/new/never/seen.c line:12345"
        assert td_utils.classify_crash(sig) == "fully_novel_crash"
        assert td_utils.classify_crash(sig) == "fully_novel_crash"

    def test_all_public_signatures(self, td_utils, agent_path):
        path = os.path.join(agent_path, "data/known_crash_signatures.json")
        with open(path) as f:
            data = json.load(f)
        for sig in data["public"]:
            assert td_utils.classify_crash(sig) == "publicly_known_crash", (
                f"Should be publicly_known: {sig}"
            )

    def test_all_non_public_not_novel(self, td_utils, agent_path):
        """Every non_public signature should classify as known (public or non-public),
        never as fully_novel_crash."""
        path = os.path.join(agent_path, "data/known_crash_signatures.json")
        with open(path) as f:
            data = json.load(f)
        for sig in data["non_public"]:
            result = td_utils.classify_crash(sig)
            assert result != "fully_novel_crash", (
                f"Should not be novel: {sig} (got {result})"
            )

    def test_all_signatures_with_prefix_not_novel(self, td_utils, agent_path):
        path = os.path.join(agent_path, "data/known_crash_signatures.json")
        with open(path) as f:
            data = json.load(f)
        for sig in data["public"]:
            prefixed = f"(MSONIC0) {sig}"
            assert td_utils.classify_crash(prefixed) == "publicly_known_crash", (
                f"Should be publicly_known with prefix: {prefixed}"
            )
        for sig in data["non_public"]:
            prefixed = f"(MSONIC0) {sig}"
            result = td_utils.classify_crash(prefixed)
            assert result != "fully_novel_crash", (
                f"Should not be novel with prefix: {prefixed} (got {result})"
            )
