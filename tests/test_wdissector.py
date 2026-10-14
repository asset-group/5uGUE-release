"""Test that WDissector C extension and tooling work correctly."""

import os


class TestWDissectorBinaries:
    def test_wdissector_so_exists(self, wdissector_path):
        so_path = os.path.join(wdissector_path, "bin/_wdissector.so")
        assert os.path.isfile(so_path)

    def test_tshark_exists(self, wdissector_path):
        tshark = os.path.join(wdissector_path, "bin/tshark")
        assert os.path.isfile(tshark)
        assert os.access(tshark, os.X_OK)

    def test_lte_fuzzer_exists(self, wdissector_path):
        fuzzer = os.path.join(wdissector_path, "bin/lte_fuzzer")
        assert os.path.isfile(fuzzer)
        assert os.access(fuzzer, os.X_OK)

    def test_editcap_exists(self, wdissector_path):
        editcap = os.path.join(wdissector_path, "bin/editcap")
        assert os.path.isfile(editcap)


class TestWDissectorImport:
    def test_swig_wrapper_importable(self):
        import wdissector

        assert hasattr(wdissector, "Machine")
        assert hasattr(wdissector, "wd_field")
        assert hasattr(wdissector, "wd_packet_dissect")

    def test_low_level_module_importable(self):
        import _wdissector

        assert _wdissector is not None


class TestWDissectorTool:
    def test_init(self, wd_tool):
        assert wd_tool.protocol == "fiveg"
        assert wd_tool.decoding_offset == 0
        assert wd_tool.wd is not None
        assert wd_tool.StateMachine is not None

    def test_state_machine_config_loaded(self, wdissector_path):
        config_path = os.path.join(wdissector_path, "configs/5gnr_gnb_config.json")
        assert os.path.isfile(config_path)

    def test_model_config_loaded(self, wdissector_path):
        config_path = os.path.join(
            wdissector_path, "configs/models/5gnr_gnb/nr-softmodem.json"
        )
        assert os.path.isfile(config_path)
