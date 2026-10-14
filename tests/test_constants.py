"""Test that all constants are correctly configured and paths exist."""

import os


class TestConstants:
    def test_paths_exist(self):
        from constants import (
            WDISSECTOR_PATH,
            AGENT_PATH,
            EXPLOIT_FOLDER,
            LOG_PATH,
            KB_PATH,
            RUN_LOG_PATH,
            RUNTIME_LOG_PATH,
            REPORTS_PATH,
            TSHARK_PATH,
            EDITCAP_PATH,
        )

        assert os.path.isdir(WDISSECTOR_PATH)
        assert os.path.isdir(AGENT_PATH)
        assert os.path.isdir(EXPLOIT_FOLDER)
        assert os.path.isdir(LOG_PATH)
        assert os.path.isdir(KB_PATH)
        assert os.path.isdir(RUN_LOG_PATH)
        assert os.path.isdir(RUNTIME_LOG_PATH)
        assert os.path.isdir(REPORTS_PATH)
        assert os.path.isfile(TSHARK_PATH)
        assert os.path.isfile(EDITCAP_PATH)

    def test_reports_path_is_host_namespaced(self):
        """REPORTS_PATH must live under REPORTS_ROOT/<HOST_ID> so eval CSVs
        sync to the master alongside the other host-namespaced subtrees."""
        from constants import REPORTS_ROOT, REPORTS_PATH, HOST_ID

        assert REPORTS_PATH == os.path.join(REPORTS_ROOT, HOST_ID)
        assert REPORTS_PATH.endswith(f"/reports/{HOST_ID}")

    def test_log_subdir_exists(self):
        # The 5gnr_gnb log subdir may live under either LOG_ROOT (legacy flat)
        # or LOG_PATH (host-namespaced) depending on whether the master-side
        # migration has run. Either is acceptable.
        from constants import LOG_ROOT, RUN_LOG_PATH

        assert os.path.isdir(os.path.join(RUN_LOG_PATH, "5gnr_gnb")) or os.path.isdir(
            os.path.join(LOG_ROOT, "5gnr_gnb")
        )

    def test_config_paths_exist(self):
        from constants import (
            FIVEG_WD_SM_CONFIG,
            FIVEG_WD_MODEL_CONFIG,
        )

        assert os.path.isfile(FIVEG_WD_SM_CONFIG)
        assert os.path.isfile(FIVEG_WD_MODEL_CONFIG)

    def test_data_paths_exist(self):
        from constants import (
            NORMAL_CAPTURE,
            FUZZ_CAPTURE,
            FIVEG_FIELDS_DESC,
            EXPLOIT_TEMPLATE,
        )

        assert os.path.isfile(NORMAL_CAPTURE)
        assert os.path.isfile(FUZZ_CAPTURE)
        assert os.path.isfile(FIVEG_FIELDS_DESC)
        assert os.path.isfile(EXPLOIT_TEMPLATE)

    def test_no_llm_agentic_fuzz_references(self):
        """Constants should not reference the upstream llm-agentic-fuzz directory."""
        from constants import (
            NORMAL_CAPTURE,
            FUZZ_CAPTURE,
            FIVEG_FIELDS_DESC,
            EXPLOIT_TEMPLATE,
        )

        for path in [NORMAL_CAPTURE, FUZZ_CAPTURE, FIVEG_FIELDS_DESC, EXPLOIT_TEMPLATE]:
            assert "llm-agentic-fuzz" not in path, (
                f"Path still references upstream: {path}"
            )

    def test_api_config(self):
        from constants import MODEL, MAX_TOKENS

        assert isinstance(MODEL, str)
        assert len(MODEL) > 0
        assert MAX_TOKENS > 0

    def test_web_search_plugin_removed(self):
        """WEB_SEARCH_PLUGIN constants were removed (OpenRouter plugin was dead code)."""
        import constants

        assert not hasattr(constants, "WEB_SEARCH_PLUGIN_ENABLED")
        assert not hasattr(constants, "WEB_SEARCH_MAX_RESULTS")

    def test_enable_lte_bs_defined(self):
        """ENABLE_LTE_BS must be defined as a boolean."""
        from constants import ENABLE_LTE_BS

        assert isinstance(ENABLE_LTE_BS, bool)


