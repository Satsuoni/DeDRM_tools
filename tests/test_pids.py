"""Kindle PID generation helpers (kgenpids / kindlepid)."""
import pytest

import kgenpids
import kindlepid


@pytest.mark.parametrize("data", [b"", b"\x00", b"hello world", bytes(range(256))])
def test_encode_decode_round_trip(data):
    encoded = kgenpids.encode(data, kgenpids.charMap1)
    assert isinstance(encoded, bytes) and len(encoded) == 2 * len(data)
    assert kgenpids.decode(encoded, kgenpids.charMap1) == data
    assert isinstance(kgenpids.decode(b"", kgenpids.charMap1), bytes)


def test_checksum_pid_appends_two_checksum_chars():
    pid = b"ABCDEFGH"
    full = kindlepid.checksumPid(pid)
    assert len(full) == 10 and full.startswith(pid)
    assert full == kindlepid.checksumPid(pid)
    assert all(c in kindlepid.letters for c in full[8:])
    assert kindlepid.checksumPid(b"ABCDEFGI") != full


def test_pid_from_serial():
    pid = kindlepid.pidFromSerial(b"B001A2B3C4D5E6F7", 7)
    assert isinstance(pid, bytes) and len(pid) == 7
    assert all(c in kindlepid.letters for c in pid)


def test_get_kindle_pids_from_serial_accepts_str_and_bytes():
    rec209, token = b"\x01" * 32, b"\x02" * 8
    as_bytes = kgenpids.getKindlePids(rec209, token, b"B001A2B3C4D5E6F7")
    as_str = kgenpids.getKindlePids(rec209, token, "B001A2B3C4D5E6F7")
    assert as_bytes == as_str
    assert len(as_bytes) == 2 and all(isinstance(p, bytes) and len(p) == 10 for p in as_bytes)
    # both PIDs carry a valid checksum
    assert all(kindlepid.checksumPid(p[:8]) == p for p in as_bytes)


def test_get_pid_list_collects_bytes_pids():
    pids = kgenpids.getPidList(b"\x01" * 32, b"\x02" * 8, serials=["B001A2B3C4D5E6F7", "B00FFFFFFFFFFFFF"])
    assert len(pids) == 4 and all(isinstance(p, bytes) for p in pids)
    assert kgenpids.getPidList(None, None, serials=None, kDatabases=None) == []
