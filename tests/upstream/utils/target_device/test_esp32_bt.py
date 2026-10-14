import pytest
from upstream.utils.target_device.esp32_bt import are_bt_crashes_equivalent


def test_are_bt_crashes_equivalent_identical():
    """Verify that character-identical crash IDs are equivalent."""
    assert are_bt_crashes_equivalent("CRASH_A", "CRASH_A") is True
    assert are_bt_crashes_equivalent("ASSERT_1|BT_TRACE", "ASSERT_1|BT_TRACE") is True


def test_are_bt_crashes_equivalent_empty_or_none():
    """Verify empty and None comparisons behave correctly."""
    assert are_bt_crashes_equivalent("", "CRASH") is False
    assert are_bt_crashes_equivalent("CRASH", None) is False
    assert are_bt_crashes_equivalent(None, None) is True
    assert are_bt_crashes_equivalent("", "") is True


def test_are_bt_crashes_equivalent_with_assert_prefix():
    """Verify that crash IDs with assert prefixes are compared correctly."""
    id1 = "[ASSERT] file:main.c line:120|BT_BACKTRACE_1"
    id2 = "[ASSERT] file:main.c line:120|BT_BACKTRACE_2"
    # Matches on the first part immediately
    assert are_bt_crashes_equivalent(id1, id2) is True

    id3 = "[ASSERT] file:main.c line:130|BT_BACKTRACE_1"
    # First part differs, but rest parts ("BT_BACKTRACE_1") match, so equivalent
    assert are_bt_crashes_equivalent(id1, id3) is True

    id4 = "[ASSERT] file:main.c line:130|BT_BACKTRACE_2"
    # First part differs, and rest parts differ, so not equivalent
    assert are_bt_crashes_equivalent(id1, id4) is False


def test_are_bt_crashes_equivalent_without_assert_prefix():
    """Verify that crash IDs starting with '|' (no assertion info) are compared via remaining parts."""
    id1 = "|BT_BACKTRACE_1"
    id2 = "|BT_BACKTRACE_2"
    assert are_bt_crashes_equivalent(id1, id2) is False

    id3 = "|BT_BACKTRACE_1"
    assert are_bt_crashes_equivalent(id1, id3) is True


def test_are_bt_crashes_equivalent_backtrace_hex_exception():
    """Verify that the first hex value in the first backtrace is allowed to differ."""
    # First backtrace has different first hex values
    id1 = "|Guru Meditation Error|Backtrace:0x40082dcd:0x3ffcc470 0x400fd74d:0x3ffcc490"
    id2 = "|Guru Meditation Error|Backtrace:0x4013205f:0x3ffcc470 0x400fd74d:0x3ffcc490"
    assert are_bt_crashes_equivalent(id1, id2) is True

    # First backtrace differs in a subsequent frame
    id3 = "|Guru Meditation Error|Backtrace:0x40082dcd:0x3ffcc470 0x400fd74d:0x3ffcc490"
    id4 = "|Guru Meditation Error|Backtrace:0x40082dcd:0x3ffcc470 0x4009999f:0x3ffcc490"
    assert are_bt_crashes_equivalent(id3, id4) is False

    # Second backtrace differs in its first frame's hex1
    id5 = "|Guru Meditation Error|Backtrace:0x40082dcd:0x3ffcc470|Backtrace:0x4013205f:0x3ffbc470"
    id6 = "|Guru Meditation Error|Backtrace:0x40082dcd:0x3ffcc470|Backtrace:0x400927a5:0x3ffbc470"
    assert are_bt_crashes_equivalent(id5, id6) is False
