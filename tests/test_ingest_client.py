import importlib
import os
import pytest


@pytest.fixture
def clean_ingest_client(tmp_path, monkeypatch):
    import ingest_client

    monkeypatch.setenv("AGENT_OUTBOX_PATH", str(tmp_path / "outbox.jsonl"))
    monkeypatch.delenv("AGENT_NO_INGEST", raising=False)
    monkeypatch.delenv("ACTIVE_FUZZ_PROTOCOL", raising=False)
    monkeypatch.delenv("ACTIVE_FUZZ_DEVICE", raising=False)
    importlib.reload(ingest_client)

    # Reset globals
    ingest_client.set_active_session_context(None, None)

    return ingest_client


def test_set_active_session_context(clean_ingest_client):
    client = clean_ingest_client
    client.set_active_session_context("fiveg", "unisoc_ud710")
    assert client._ACTIVE_PROTOCOL == "fiveg"
    assert client._ACTIVE_DEVICE == "unisoc_ud710"


def test_enqueue_matching_context_succeeds(clean_ingest_client):
    client = clean_ingest_client
    client.set_active_session_context("fiveg", "unisoc_ud710")

    # This should succeed without raising ValueError
    client.enqueue("turn", {"protocol": "fiveg", "device": "unisoc_ud710"})


def test_enqueue_mismatched_protocol_raises_error(clean_ingest_client):
    client = clean_ingest_client
    client.set_active_session_context("fiveg", "unisoc_ud710")

    with pytest.raises(ValueError) as excinfo:
        client.enqueue("turn", {"protocol": "bt", "device": "unisoc_ud710"})

    assert "Ingest payload protocol 'bt' does not match active context protocol 'fiveg'" in str(excinfo.value)


def test_enqueue_mismatched_device_raises_error(clean_ingest_client):
    client = clean_ingest_client
    client.set_active_session_context("fiveg", "unisoc_ud710")

    with pytest.raises(ValueError) as excinfo:
        client.enqueue("turn", {"protocol": "fiveg", "device": "mediatek"})

    assert "Ingest payload device 'mediatek' does not match active context device 'unisoc_ud710'" in str(excinfo.value)


def test_enqueue_env_variable_validation(clean_ingest_client, monkeypatch):
    client = clean_ingest_client
    # Make sure session context globals are None
    client.set_active_session_context(None, None)

    # Set env context variables
    monkeypatch.setenv("ACTIVE_FUZZ_PROTOCOL", "bt")
    monkeypatch.setenv("ACTIVE_FUZZ_DEVICE", "esp32")

    # Mismatched protocol should raise error
    with pytest.raises(ValueError) as excinfo:
        client.enqueue("turn", {"protocol": "fiveg", "device": "esp32"})
    assert "protocol 'fiveg' does not match active context protocol 'bt'" in str(excinfo.value)

    # Mismatched device should raise error
    with pytest.raises(ValueError) as excinfo:
        client.enqueue("turn", {"protocol": "bt", "device": "mediatek"})
    assert "device 'mediatek' does not match active context device 'esp32'" in str(excinfo.value)

    # Matching values should succeed
    client.enqueue("turn", {"protocol": "bt", "device": "esp32"})
