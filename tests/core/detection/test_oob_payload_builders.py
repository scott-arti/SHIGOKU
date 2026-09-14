"""SGK-2026-0496: OOB payload builder（デシリアライズ・コールバックガジェット）の検証。
生成物は unpickle しない（実行を避ける）＝バイト列の中身を検査するのみ。製品非依存。"""

import pytest

from src.core.detection.oob_payload_builders import build_oob_payload, encode_payload


_CB = "http://127.0.0.1:13337/callback/abcd1234"


def test_python_pickle_contains_callback_and_os_system():
    raw = build_oob_payload("python_pickle", _CB)
    assert isinstance(raw, bytes)
    # os.system への __reduce__ 参照とコールバック URL がバイト列に含まれる（unpickle しない）。
    assert b"system" in raw
    assert _CB.encode() in raw


def test_unknown_builder_raises():
    with pytest.raises(ValueError):
        build_oob_payload("no_such_builder", _CB)


def test_encode_hex_roundtrips_to_same_bytes():
    raw = build_oob_payload("python_pickle", _CB)
    hexed = encode_payload(raw, "hex")
    assert isinstance(hexed, str)
    assert bytes.fromhex(hexed) == raw


def test_encode_base64():
    import base64
    raw = build_oob_payload("python_pickle", _CB)
    b64 = encode_payload(raw, "base64")
    assert base64.b64decode(b64) == raw


def test_encode_raw_passthrough():
    raw = build_oob_payload("python_pickle", _CB)
    assert encode_payload(raw, "raw") == raw


def test_fresh_callback_changes_payload():
    a = build_oob_payload("python_pickle", "http://x/callback/aaaa1111")
    b = build_oob_payload("python_pickle", "http://x/callback/bbbb2222")
    assert a != b  # fresh callback ごとに別ペイロード（封印再現の隔離）
