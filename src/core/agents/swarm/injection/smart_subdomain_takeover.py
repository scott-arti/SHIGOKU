"""
Smart Subdomain Takeover Hunter - サブドメイン乗っ取り 検出スペシャリスト (SGK-2026-0493)

サブドメインの DNS（多くは CNAME）が第三者サービス（S3 / GitHub Pages / Heroku / Azure 等）を
指したまま、その先のリソースが削除・未登録（dangling）だと、攻撃者がそのリソースを登録して
サブドメインの内容を支配できる（Subdomain Takeover）。

**確度は ◯（候補検出）**。本エンジンは**非破壊のフィンガープリント検出のみ**を行う：
  - CNAME（または host 名）が既知プロバイダの fingerprint_domain に一致（＝そのプロバイダへ委譲）
  - 取得本文にそのプロバイダの「未登録リソース」を示す error_token が出現（例: GitHub Pages の
    "There isn't a GitHub Pages site here"、S3 の "NoSuchBucket"）
両者が同一プロバイダで揃えば takeover 候補（高確度）。error_token のみでも候補（中確度）。
**完全な証明（◎）は実際にリソースを登録して奪取する必要があり破壊的・スコープ外**のため本エンジン
では行わず、finding に claim_prerequisites / verification_urls を載せて**人手での確認**に委ねる
（[[detection-capability-wiring-map]]・CORS と同じく本物確定能力＝◯）。プロバイダ表は
`config/providers/takeover_provider_matrix.yaml`（`can-i-take-over-xyz` 由来の実フィンガープリント）。
"""
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.adapters.external.takeover_provider_matrix_adapter import (
    ProviderMatrixLoader,
    TakeoverProviderMatrix,
)

logger = logging.getLogger(__name__)

_DEFAULT_MATRIX_PATH = "config/providers/takeover_provider_matrix.yaml"
_TO_SNIPPET_CAP = 800


def _host_of(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    return (urlsplit(target).hostname or "").lower()


def _snippet(body: str, token: str) -> str:
    body = body or ""
    idx = body.find(token) if token else -1
    if idx < 0:
        return body[:_TO_SNIPPET_CAP]
    start = max(0, idx - _TO_SNIPPET_CAP // 2)
    return body[start:start + _TO_SNIPPET_CAP]


class SmartSubdomainTakeoverHunter(Specialist):
    name = "SmartSubdomainTakeoverHunter"
    description = "Subdomain takeover candidate detector (non-destructive fingerprint; grade ○)"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}
        self._matrix: Optional[TakeoverProviderMatrix] = None

    def _load_matrix(self, task: Task) -> Optional[TakeoverProviderMatrix]:
        if self._matrix is not None:
            return self._matrix
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        path = str(params.get("takeover_matrix_path") or _DEFAULT_MATRIX_PATH)
        try:
            loader = ProviderMatrixLoader()
            loader.load(path)
            self._matrix = TakeoverProviderMatrix(loader)
        except Exception as exc:  # noqa: BLE001 — config load boundary, fail closed
            logger.warning("[%s] provider matrix load failed (%s): %s", self.name, path, exc)
            return None
        return self._matrix

    def _targets(self, task: Task) -> List[Tuple[str, str]]:
        """(url, cname) のリストを返す。cname は task 由来（recon）があれば使う。"""
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        out: List[Tuple[str, str]] = []
        subs = params.get("takeover_subdomains")
        if isinstance(subs, (list, tuple)):
            for s in subs:
                if isinstance(s, dict):
                    url = str(s.get("url") or s.get("host") or "").strip()
                    cname = str(s.get("cname") or "").strip()
                    if url:
                        out.append((url, cname))
                elif isinstance(s, str) and s.strip():
                    out.append((s.strip(), ""))
        if task.target:
            out.append((str(task.target), str(params.get("cname") or "")))
        return out

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        matrix = self._load_matrix(task)
        if matrix is None:
            return []
        findings: List[Finding] = []
        for url, cname in self._targets(task):
            f = await self._probe_one(url, cname, matrix)
            if f is not None:
                findings.append(f)
        return findings

    async def _probe_one(
        self, url: str, cname: str, matrix: TakeoverProviderMatrix
    ) -> Optional[Finding]:
        host = _host_of(url)
        # CNAME 未提供なら host 名で代用（サブドメインが直接プロバイダ配下のケースを拾う）。
        cname_candidate = (cname or host).lower()
        provider_by_cname = matrix.find_by_fingerprint_domain(cname_candidate)
        try:
            status, body = await self._send(url)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] fetch failed (%s): %s", self.name, url, exc)
            return None
        provider_by_error = matrix.find_by_error_token(body)
        if provider_by_error is None:
            # 未登録サインが無い＝乗っ取り候補ではない（fail-closed）。
            return None

        matched_token = next(
            (t for t in provider_by_error.error_tokens if t in body), ""
        )
        fp_twin = next(
            (t for t in provider_by_error.false_positive_twins if t and t in body), ""
        )
        cname_match = (
            provider_by_cname is not None
            and provider_by_cname.provider_id == provider_by_error.provider_id
        )
        confidence = 0.9 if cname_match else 0.6
        return self._build_finding(
            url=url, host=host, cname=cname_candidate, status=status, body=body,
            provider=provider_by_error, matched_token=matched_token,
            cname_match=cname_match, fp_twin=fp_twin, confidence=confidence,
        )

    async def _send(self, url: str) -> Tuple[int, str]:
        if "://" not in url:
            url = "https://" + url

        async def _do(client):
            return await client.request("GET", url, use_proxy=True)

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

    def _build_finding(
        self, *, url: str, host: str, cname: str, status: int, body: str,
        provider: Any, matched_token: str, cname_match: bool, fp_twin: str,
        confidence: float,
    ) -> Finding:
        provider_id = provider.provider_id
        snippet = _snippet(body, matched_token)
        conf_word = "高（CNAME 委譲＋未登録サイン一致）" if cname_match else "中（未登録サインのみ）"
        caution = (
            f" ただし false-positive twin '{fp_twin}' も本文にあるため誤検知の可能性に注意。"
            if fp_twin else ""
        )
        impact = (
            f"サブドメイン {host} は '{provider_id}'（{cname}）へ委譲されているが、取得本文に未登録"
            f"リソースのサイン '{matched_token}' が出ている（確度 {conf_word}）。攻撃者が {provider_id} で"
            "当該リソースを登録すると、このサブドメインの内容を支配できる（Subdomain Takeover 候補）。"
            "完全な確定には人手で実際にリソースを登録して奪取確認が必要（破壊的・要承認＝本エンジンは"
            f"非破壊のフィンガープリント検出まで）。{caution}"
        )
        verification_urls = list(getattr(provider, "verification_urls", []) or [])
        claim_prereq = list(getattr(provider, "claim_prerequisites", []) or [])
        return Finding(
            target_url=url,
            vuln_type=VulnType.SUBDOMAIN_TAKEOVER,
            severity=Severity.HIGH,
            title=f"Subdomain Takeover candidate: {host} ({provider_id})",
            description=(
                f"Dangling delegation to '{provider_id}' with unclaimed-resource fingerprint "
                f"'{matched_token}' in the response body (confidence "
                f"{'high' if cname_match else 'medium'}). Non-destructive fingerprint only; "
                "a human must claim the resource to confirm (grade ○)."
            ),
            source_agent=self.name,
            confidence=confidence,
            impact=impact,
            reproduction_steps=[
                f"{url} を取得し、本文に '{provider_id}' の未登録サイン '{matched_token}' が出ることを"
                "確認する（非破壊）。",
                f"CNAME/host が '{provider_id}' の fingerprint domain に一致することを確認する"
                f"（{'一致' if cname_match else '未確認'}）。",
                "（人手・要承認）verification_urls から実際にリソースを登録し、当該サブドメインに"
                "自分のマーカーが出れば takeover 確定（破壊的のため自動では行わない）。",
            ],
            tags=["subdomain_takeover", "high", "candidate", provider_id],
            evidence=Evidence(
                request_method="GET",
                request_url=url,
                request_headers={},
                request_body="",
                response_status=status,
                response_headers={},
                response_body=snippet,
            ),
            additional_info={
                "subdomain_takeover_evidence": {
                    "host": host,
                    "cname": cname,
                    "provider_id": provider_id,
                    "matched_error_token": matched_token,
                    "cname_provider_match": cname_match,
                    "response_status": status,
                    "served_body": snippet,
                    "false_positive_twin": fp_twin,
                    "confidence": confidence,
                    "grade": "candidate",  # ○: 破壊的奪取は未実施（人手確認に委ねる）
                    "claim_prerequisites": claim_prereq,
                    "verification_urls": verification_urls,
                },
            },
        )
