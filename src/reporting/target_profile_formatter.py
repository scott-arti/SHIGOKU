"""
TargetProfileFormatter: セッションJSONデータから日本語の target_profile.md を生成するフォーマッター

単一セッションのスナップショットを元に、ターゲットのプロファイルレポートを生成する。
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from src.reporting.finding_extractor import extract_all_findings

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback only
    ZoneInfo = None


@dataclass
class UrlAsset:
    """URL資産の内部表現"""
    url: str
    kind: str = "page"  # page, api, admin, auth, other
    discovered_by: str = ""
    note: str = ""

    def shortened_url(self) -> str:
        """クエリパラメータを除去した短縮URLを返す（機微情報マスク）"""
        if not self.url:
            return ""
        split = urlsplit(self.url)
        if split.scheme and split.netloc:
            return urlunsplit((split.scheme.lower(), split.netloc, split.path or "/", "", ""))
        return self.url


class TargetProfileFormatter:
    """
    セッションJSONデータから日本語 target_profile.md を生成する。

    主な利用方法:
        formatter = TargetProfileFormatter()
        markdown = formatter.format(session_data)
    """

    def __init__(self):
        self._session: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # ユーティリティ
    # ------------------------------------------------------------------

    @staticmethod
    def _now_jst() -> datetime:
        if ZoneInfo is not None:
            try:
                return datetime.now(ZoneInfo("Asia/Tokyo"))
            except Exception:
                pass
        return datetime.now(timezone(timedelta(hours=9)))

    @staticmethod
    def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
        """ネストされた辞書から安全に値を取得する。途中で非辞書に当たったら default を返す。"""
        current = d
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, default)
            elif isinstance(current, list):
                try:
                    idx = int(key)
                    current = current[idx]
                except (ValueError, IndexError):
                    return default
            else:
                return default
        return current

    @staticmethod
    def _safe_list(value: Any) -> List[Any]:
        """安全にリストを返す。None や非リストの場合は空リスト。"""
        if isinstance(value, list):
            return value
        return []

    @staticmethod
    def _safe_dict(value: Any) -> Dict[str, Any]:
        """安全に辞書を返す。None や非辞書の場合は空辞書。"""
        if isinstance(value, dict):
            return value
        return {}

    @staticmethod
    def _safe_str(value: Any, default: str = "") -> str:
        """安全に文字列を返す。None の場合は default。"""
        if value is None:
            return default
        return str(value)

    @staticmethod
    def _normalize_url(value: str) -> str:
        """URL 文字列を表示用に正規化する。"""
        if not value:
            return ""
        normalized = str(value).strip()
        if normalized.startswith("http:/") and not normalized.startswith("http://"):
            normalized = normalized.replace("http:/", "http://", 1)
        if normalized.startswith("https:/") and not normalized.startswith("https://"):
            normalized = normalized.replace("https:/", "https://", 1)
        split = urlsplit(normalized)
        if split.scheme and split.netloc:
            return urlunsplit((split.scheme.lower(), split.netloc, split.path or "/", "", ""))
        return normalized

    @staticmethod
    def _is_truthy(value: Any) -> bool:
        """値が truthy かどうか（None, 空文字, 空リスト, 空辞書を除く）。"""
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return True
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, dict)):
            return bool(value)
        return True

    def _no_data_section(self, section_name: str) -> str:
        """データがないセクション用の定型メッセージを返す。"""
        return f"{section_name}なし (No data in source session)"

    # ------------------------------------------------------------------
    # セクション1: ターゲット概要
    # ------------------------------------------------------------------

    def _section_1_target_overview(self) -> str:
        lines: List[str] = []
        lines.append("## 1. ターゲット概要")
        lines.append("")

        target_info = self._safe_dict(self._safe_get(self._session, "context", "target_info"))

        has_data = False

        url = self._safe_str(target_info.get("url", ""))
        if url:
            lines.append(f"- ターゲットURL: `{self._normalize_url(url)}`")
            lines.append(f"  - source: context.target_info.url")
            has_data = True

        domain = self._safe_str(target_info.get("domain", ""))
        if domain:
            lines.append(f"- ドメイン: `{domain}`")
            lines.append(f"  - source: context.target_info.domain")
            has_data = True

        # domains (list)
        domains = self._safe_list(target_info.get("domains", []))
        if domains:
            domain_str = ", ".join(f"`{d}`" for d in domains if d)
            if domain_str:
                lines.append(f"- 関連ドメイン: {domain_str}")
                lines.append(f"  - source: context.target_info.domains")
                has_data = True

        # IP addresses
        ip_addresses = self._safe_list(target_info.get("ip_addresses", []))
        if ip_addresses:
            ip_str = ", ".join(f"`{ip}`" for ip in ip_addresses if ip)
            if ip_str:
                lines.append(f"- IPアドレス: {ip_str}")
                lines.append(f"  - source: context.target_info.ip_addresses")
                has_data = True

        # セッション識別子
        session_id = self._safe_str(self._session.get("session_id", ""))
        if not session_id:
            session_id = self._safe_str(self._safe_get(self._session, "context", "session_id", ""))
        if session_id:
            lines.append(f"- セッションID: `{session_id}`")
            has_data = True

        # 検出日時
        start_time = self._safe_get(self._session, "context", "start_time")
        if not start_time:
            start_time = self._session.get("start_time")
        if start_time:
            try:
                if isinstance(start_time, str):
                    dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                elif isinstance(start_time, (int, float)):
                    dt = datetime.fromtimestamp(start_time, tz=timezone.utc)
                else:
                    dt = None
                if dt:
                    lines.append(f"- 検出日時: {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                    has_data = True
            except (ValueError, TypeError, OverflowError):
                lines.append(f"- 検出日時(生データ): {start_time}")
                has_data = True

        if not has_data:
            lines.append(self._no_data_section("ターゲット情報"))

        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション2: 検出機能概要
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_feature(url: str, extra_tags: Optional[List[str]] = None) -> str:
        """URL や追加タグから機能種別を分類する。"""
        tags = [t.lower().strip() for t in (extra_tags or []) if t]
        url_lower = (url or "").lower()

        if "admin" in url_lower or "admin" in tags:
            return "admin"
        if "api" in url_lower or "api" in tags or "/graphql" in url_lower:
            return "API"
        if "auth" in tags or "login" in url_lower or "signin" in url_lower or "oauth" in url_lower:
            return "auth-related"
        return "page"

    def _section_2_discovered_features(self) -> str:
        lines: List[str] = []
        lines.append("## 2. 検出機能概要")
        lines.append("")

        target_info = self._safe_dict(self._safe_get(self._session, "context", "target_info"))
        completed_tasks = self._safe_list(self._session.get("completed_tasks", []))

        features: List[Dict[str, str]] = []

        # target_info の pages_discovered
        pages = self._safe_list(target_info.get("pages_discovered", []))
        for page in pages:
            if isinstance(page, dict):
                url = self._safe_str(page.get("url", page.get("path", "")))
                if url:
                    features.append({
                        "url": self._normalize_url(url),
                        "type": "page",
                        "source": "context.target_info.pages_discovered",
                    })
            elif isinstance(page, str):
                features.append({
                    "url": self._normalize_url(page),
                    "type": "page",
                    "source": "context.target_info.pages_discovered",
                })

        # target_info の api_endpoints
        api_endpoints = self._safe_list(target_info.get("api_endpoints", []))
        for ep in api_endpoints:
            if isinstance(ep, dict):
                url = self._safe_str(ep.get("url", ep.get("path", ep.get("endpoint", ""))))
                if url:
                    features.append({
                        "url": self._normalize_url(url),
                        "type": "API",
                        "source": "context.target_info.api_endpoints",
                    })
            elif isinstance(ep, str):
                features.append({
                    "url": self._normalize_url(ep),
                    "type": "API",
                    "source": "context.target_info.api_endpoints",
                })

        # completed_tasks の target_url
        for task in completed_tasks:
            if not isinstance(task, dict):
                continue
            task_url = self._safe_str(task.get("target_url", ""))
            if not task_url:
                continue
            url = self._normalize_url(task_url)
            task_id = self._safe_str(task.get("task_id", task.get("id", "")))
            vulns = self._safe_list(task.get("vulnerabilities_found", []))
            tags = self._safe_list(task.get("tags", []))
            feature_type = self._classify_feature(url, tags)
            features.append({
                "url": url,
                "type": feature_type,
                "source": f"completed_tasks.{task_id}" if task_id else "completed_tasks",
            })

        if not features:
            lines.append(self._no_data_section("機能情報"))
            lines.append("")
            return "\n".join(lines)

        # 重複排除
        seen: set = set()
        unique_features: List[Dict[str, str]] = []
        for f in features:
            key = (f["url"], f["type"])
            if key not in seen:
                seen.add(key)
                unique_features.append(f)

        # 種別ごとにグループ化
        by_type: Dict[str, List[Dict[str, str]]] = {}
        for f in unique_features:
            t = f["type"]
            by_type.setdefault(t, []).append(f)

        for ftype in ("page", "API", "admin", "auth-related"):
            items = by_type.get(ftype, [])
            if not items:
                continue
            label = {"page": "ページ", "API": "APIエンドポイント", "admin": "管理機能", "auth-related": "認証関連機能"}.get(ftype, ftype)
            lines.append(f"### {label}")
            lines.append("")
            for item in items:
                lines.append(f"- `{item['url']}`")
                lines.append(f"  - source: {item['source']}")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション3: 技術スタック
    # ------------------------------------------------------------------

    def _section_3_tech_stack(self) -> str:
        lines: List[str] = []
        lines.append("## 3. 技術スタック")
        lines.append("")

        target_info = self._safe_dict(self._safe_get(self._session, "context", "target_info"))
        has_data = False

        # tech_stack
        tech_stack = self._safe_get(target_info, "tech_stack")
        if tech_stack:
            if isinstance(tech_stack, dict):
                for k, v in tech_stack.items():
                    lines.append(f"- {k}: `{v}`")
                    has_data = True
            elif isinstance(tech_stack, list):
                for item in tech_stack:
                    if isinstance(item, dict):
                        name = self._safe_str(item.get("name", item.get("technology", "")))
                        version = self._safe_str(item.get("version", ""))
                        line = f"- {name}"
                        if version:
                            line += f" (v{version})"
                        lines.append(line)
                    elif isinstance(item, str):
                        lines.append(f"- {item}")
                has_data = True
            elif isinstance(tech_stack, str):
                lines.append(f"- {tech_stack}")
                has_data = True
            if has_data:
                lines.append(f"  - source: context.target_info.tech_stack")
                lines.append("")

        # fingerprint_metadata
        fp_meta = self._safe_get(target_info, "fingerprint_metadata")
        if fp_meta:
            if isinstance(fp_meta, dict):
                fp_has = False
                for k, v in fp_meta.items():
                    lines.append(f"- {k}: `{v}`")
                    fp_has = True
                if fp_has:
                    lines.append(f"  - source: context.target_info.fingerprint_metadata")
                    has_data = True
                    lines.append("")
            elif isinstance(fp_meta, str):
                lines.append(f"- Fingerprint: {fp_meta}")
                lines.append(f"  - source: context.target_info.fingerprint_metadata")
                has_data = True
                lines.append("")

        # detected_services
        services = self._safe_list(target_info.get("detected_services", []))
        if services:
            lines.append("### 検出サービス")
            lines.append("")
            for svc in services:
                if isinstance(svc, dict):
                    name = self._safe_str(svc.get("name", svc.get("service", "")))
                    version = self._safe_str(svc.get("version", ""))
                    port = self._safe_str(svc.get("port", ""))
                    parts = [name]
                    if version:
                        parts.append(f"v{version}")
                    if port:
                        parts.append(f"(port {port})")
                    lines.append(f"- {' '.join(parts)}")
                elif isinstance(svc, str):
                    lines.append(f"- {svc}")
            lines.append(f"  - source: context.target_info.detected_services")
            has_data = True
            lines.append("")

        if not has_data:
            lines.append(self._no_data_section("技術スタック情報"))
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション4: 認証機構
    # ------------------------------------------------------------------

    def _section_4_auth_mechanisms(self) -> str:
        lines: List[str] = []
        lines.append("## 4. 認証機構")
        lines.append("")

        target_info = self._safe_dict(self._safe_get(self._session, "context", "target_info"))
        has_data = False

        # auth_mechanisms
        auth_mechs = self._safe_get(target_info, "auth_mechanisms")
        if auth_mechs:
            if isinstance(auth_mechs, list):
                for mech in auth_mechs:
                    if isinstance(mech, dict):
                        name = self._safe_str(mech.get("name", mech.get("type", "")))
                        desc = self._safe_str(mech.get("description", mech.get("details", "")))
                        line = f"- {name}"
                        if desc:
                            line += f": {desc}"
                        lines.append(line)
                    elif isinstance(mech, str):
                        lines.append(f"- {mech}")
                lines.append(f"  - source: context.target_info.auth_mechanisms")
                has_data = True
            elif isinstance(auth_mechs, str):
                lines.append(f"- {auth_mechs}")
                lines.append(f"  - source: context.target_info.auth_mechanisms")
                has_data = True

        # セッション管理 (target_info 内の関連フィールド)
        session_mgmt = self._safe_get(target_info, "session_management")
        if session_mgmt:
            if isinstance(session_mgmt, dict):
                for k, v in session_mgmt.items():
                    lines.append(f"- セッション管理 ({k}): `{v}`")
                lines.append(f"  - source: context.target_info.session_management")
                has_data = True
            elif isinstance(session_mgmt, str):
                lines.append(f"- セッション管理: {session_mgmt}")
                lines.append(f"  - source: context.target_info.session_management")
                has_data = True

        # 認可モデル
        authz_model = self._safe_get(target_info, "authorization_model")
        if not authz_model:
            authz_model = self._safe_get(target_info, "authz_model")
        if authz_model:
            if isinstance(authz_model, dict):
                for k, v in authz_model.items():
                    lines.append(f"- 認可モデル ({k}): `{v}`")
                lines.append(f"  - source: context.target_info.authorization_model")
                has_data = True
            elif isinstance(authz_model, str):
                lines.append(f"- 認可モデル: {authz_model}")
                lines.append(f"  - source: context.target_info.authorization_model")
                has_data = True

        # completed_tasks から認証関連情報を抽出
        completed_tasks = self._safe_list(self._session.get("completed_tasks", []))
        auth_from_tasks: List[Dict[str, str]] = []
        for task in completed_tasks:
            if not isinstance(task, dict):
                continue
            tags = self._safe_list(task.get("tags", []))
            task_id = self._safe_str(task.get("task_id", task.get("id", "")))
            if any(t.lower() in ("auth", "authentication", "oauth", "jwt", "session") for t in tags if isinstance(t, str)):
                note = self._safe_str(task.get("note", task.get("summary", "")))
                if note:
                    auth_from_tasks.append({"note": note, "task_id": task_id})

        if auth_from_tasks:
            if not has_data:
                lines.append("### タスク結果からの認証情報")
                lines.append("")
            for item in auth_from_tasks:
                lines.append(f"- {item['note']}")
                lines.append(f"  - source: completed_tasks.{item['task_id']}" if item['task_id'] else "  - source: completed_tasks")
            has_data = True

        if not has_data:
            lines.append(self._no_data_section("認証情報"))
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション5: URL・API・ページ統計
    # ------------------------------------------------------------------

    def _collect_urls_from_session(self) -> List[UrlAsset]:
        """セッション内の全URLを収集し、UrlAsset のリストとして返す。"""
        assets: List[UrlAsset] = []

        # context.target_info.pages_discovered
        target_info = self._safe_dict(self._safe_get(self._session, "context", "target_info"))
        pages = self._safe_list(target_info.get("pages_discovered", []))
        for page in pages:
            if isinstance(page, dict):
                url = self._safe_str(page.get("url", page.get("path", "")))
                if url:
                    assets.append(UrlAsset(
                        url=self._normalize_url(url),
                        kind="page",
                        discovered_by="context.target_info.pages_discovered",
                    ))
            elif isinstance(page, str):
                assets.append(UrlAsset(
                    url=self._normalize_url(page),
                    kind="page",
                    discovered_by="context.target_info.pages_discovered",
                ))

        # context.target_info.api_endpoints
        api_endpoints = self._safe_list(target_info.get("api_endpoints", []))
        for ep in api_endpoints:
            if isinstance(ep, dict):
                url = self._safe_str(ep.get("url", ep.get("path", ep.get("endpoint", ""))))
                if url:
                    assets.append(UrlAsset(
                        url=self._normalize_url(url),
                        kind="API",
                        discovered_by="context.target_info.api_endpoints",
                    ))
            elif isinstance(ep, str):
                assets.append(UrlAsset(
                    url=self._normalize_url(ep),
                    kind="API",
                    discovered_by="context.target_info.api_endpoints",
                ))

        # context.discovered_assets
        discovered = self._safe_list(self._safe_get(self._session, "context", "discovered_assets", default=[]))
        for asset in discovered:
            if isinstance(asset, dict):
                url = self._safe_str(asset.get("url", asset.get("target_url", "")))
                if url:
                    kind = self._safe_str(asset.get("type", asset.get("kind", "page")))
                    assets.append(UrlAsset(
                        url=self._normalize_url(url),
                        kind=kind if kind else "page",
                        discovered_by="context.discovered_assets",
                        note=self._safe_str(asset.get("note", asset.get("description", ""))),
                    ))
            elif isinstance(asset, str):
                assets.append(UrlAsset(
                    url=self._normalize_url(asset),
                    kind="page",
                    discovered_by="context.discovered_assets",
                ))

        # completed_tasks の target_url
        completed_tasks = self._safe_list(self._session.get("completed_tasks", []))
        for task in completed_tasks:
            if not isinstance(task, dict):
                continue
            url = self._safe_str(task.get("target_url", ""))
            if not url:
                continue
            task_id = self._safe_str(task.get("task_id", task.get("id", "")))
            vulns = self._safe_list(task.get("vulnerabilities_found", []))
            tags = self._safe_list(task.get("tags", []))
            assets.append(UrlAsset(
                url=self._normalize_url(url),
                kind=self._classify_feature(url, tags),
                discovered_by=f"completed_tasks.{task_id}" if task_id else "completed_tasks",
                note=f"vulns={len(vulns)}" if vulns else "",
            ))

        # task_execution_records の target_url
        records = self._safe_list(self._session.get("task_execution_records", []))
        for rec in records:
            if not isinstance(rec, dict):
                continue
            url = self._safe_str(rec.get("target_url", ""))
            if not url:
                url = self._safe_str(rec.get("url", ""))
            if not url:
                continue
            rec_id = self._safe_str(rec.get("record_id", rec.get("id", rec.get("task_id", ""))))
            assets.append(UrlAsset(
                url=self._normalize_url(url),
                kind="page",
                discovered_by=f"task_execution_records.{rec_id}" if rec_id else "task_execution_records",
            ))

        # 重複排除（URL 正規化後）
        seen: Dict[str, UrlAsset] = {}
        for asset in assets:
            key = asset.url
            if key in seen:
                existing = seen[key]
                if not existing.kind or existing.kind == "page":
                    if asset.kind and asset.kind != "page":
                        existing.kind = asset.kind
                if not existing.discovered_by:
                    existing.discovered_by = asset.discovered_by
                if not existing.note:
                    existing.note = asset.note
            else:
                seen[key] = UrlAsset(
                    url=asset.url,
                    kind=asset.kind,
                    discovered_by=asset.discovered_by,
                    note=asset.note,
                )

        return list(seen.values())

    def _section_5_url_statistics(self) -> str:
        lines: List[str] = []
        lines.append("## 5. URL・API・ページ統計")
        lines.append("")

        assets = self._collect_urls_from_session()

        if not assets:
            lines.append(self._no_data_section("URL/APIデータ"))
            lines.append("")
            return "\n".join(lines)

        # テーブル
        lines.append("| 種別 | URL | 発見元 | 備考 |")
        lines.append("|------|-----|--------|------|")
        for asset in assets:
            kind_label = {"page": "ページ", "API": "API", "admin": "管理", "auth-related": "認証関連"}.get(asset.kind, asset.kind)
            url_short = asset.shortened_url()
            if len(url_short) > 60:
                url_short = url_short[:57] + "..."
            discovered = asset.discovered_by or "-"
            note = asset.note or "-"
            lines.append(f"| {kind_label} | `{url_short}` | {discovered} | {note} |")
        lines.append("")

        # 集計
        total_pages = sum(1 for a in assets if a.kind == "page")
        total_apis = sum(1 for a in assets if a.kind == "API")
        total_admin = sum(1 for a in assets if a.kind == "admin")
        total_auth = sum(1 for a in assets if a.kind == "auth-related")
        total_unique = len(assets)

        lines.append("### 集計サマリ")
        lines.append("")
        lines.append(f"- 総ユニークURL数: {total_unique}")
        lines.append(f"- ページ数: {total_pages}")
        lines.append(f"- API数: {total_apis}")
        lines.append(f"- 管理機能数: {total_admin}")
        lines.append(f"- 認証関連数: {total_auth}")
        lines.append("")
        lines.append("集計方法: `context.target_info.pages_discovered`, `context.target_info.api_endpoints`, `completed_tasks`, `task_execution_records`, `context.discovered_assets` の `target_url` を重複排除して集計")
        lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション6: 攻撃面分析
    # ------------------------------------------------------------------

    def _section_6_attack_surface(self) -> str:
        lines: List[str] = []
        lines.append("## 6. 攻撃面分析")
        lines.append("")

        all_findings = extract_all_findings(self._session)

        # カテゴリ定義
        categories: Dict[str, Dict[str, Any]] = {
            "認証": {"count": 0, "finding_ids": [], "keywords": ["auth", "login", "token", "jwt", "oauth", "credential", "password"]},
            "認可": {"count": 0, "finding_ids": [], "keywords": ["access_control", "authorization", "idor", "bola", "bfla", "privilege", "role"]},
            "入力検証": {"count": 0, "finding_ids": [], "keywords": ["xss", "sqli", "injection", "validation", "crlf", "ssti", "deserialize"]},
            "セッション管理": {"count": 0, "finding_ids": [], "keywords": ["session", "csrf", "cookie", "logout"]},
            "API": {"count": 0, "finding_ids": [], "keywords": ["api", "graphql", "cors", "openapi", "swagger"]},
            "ビジネスロジック": {"count": 0, "finding_ids": [], "keywords": ["business_logic", "mass_assignment", "workflow", "race_condition"]},
        }

        def _match_category(text: str) -> Optional[str]:
            text_lower = text.lower()
            for cat_name, cat_info in categories.items():
                for kw in cat_info["keywords"]:
                    if kw in text_lower:
                        return cat_name
            return None

        # all_findings から集計 (covers both session.findings and result.* deep paths)
        for finding in all_findings:
            if not isinstance(finding, dict):
                continue
            ftype = self._safe_str(finding.get("vuln_type", finding.get("type", "")))
            title = self._safe_str(finding.get("title", ""))
            combined = f"{ftype} {title}"
            cat = _match_category(combined)
            if cat:
                categories[cat]["count"] += 1
                fid = self._safe_str(finding.get("finding_id", finding.get("id", "")))
                if fid:
                    categories[cat]["finding_ids"].append(fid)

        total_findings = sum(c["count"] for c in categories.values())

        if total_findings == 0:
            lines.append(self._no_data_section("攻撃面データ"))
            lines.append("")
            return "\n".join(lines)

        lines.append(f"総Finding数: {total_findings}")
        lines.append("")
        lines.append("| 攻撃面カテゴリ | Finding数 | 割合 |")
        lines.append("|----------------|-----------|------|")
        for cat_name, cat_info in categories.items():
            count = cat_info["count"]
            if count == 0:
                continue
            pct = (count / total_findings * 100.0) if total_findings > 0 else 0.0
            lines.append(f"| {cat_name} | {count} | {pct:.1f}% |")
        lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション7: Finding・仮説一覧
    # ------------------------------------------------------------------

    def _section_7_findings_list(self) -> str:
        lines: List[str] = []
        lines.append("## 7. Finding・仮説一覧")
        lines.append("")

        raw_findings = extract_all_findings(self._session)
        all_findings: List[Dict[str, Any]] = []

        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            # Determine source for traceability
            src_task_id = self._safe_str(f.get("_source_task_id", ""))
            source = f"completed_tasks.{src_task_id}" if src_task_id else "findings"

            all_findings.append({
                "title": self._safe_str(f.get("title", "")),
                "severity": self._safe_str(f.get("severity", "info")),
                "vuln_type": self._safe_str(f.get("vuln_type", f.get("type", "unknown"))),
                "url": self._normalize_url(self._safe_str(f.get("target_url", f.get("url", "")))),
                "confidence": self._safe_str(f.get("confidence", "")),
                "source": source,
                "id": self._safe_str(f.get("finding_id", f.get("id", src_task_id))),
                "heuristic": bool(f.get("heuristic_candidate", f.get("verification_required", False))),
            })

        if not all_findings:
            lines.append("発見事項なし")
            lines.append("")
            return "\n".join(lines)

        lines.append("| Finding | Finding ID | 深刻度 | 種別 | URL | 確度 | 発見元 |")
        lines.append("|---------|------------|--------|------|-----|------|--------|")

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda x: severity_order.get(x["severity"].lower(), 99))

        for f in all_findings:
            title = f["title"]
            if len(title) > 50:
                title = title[:47] + "..."
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(f["severity"].lower(), "⚪")
            sev_display = f"{sev_emoji} {f['severity'].upper()}"
            confidence = "推定" if f["heuristic"] else "確認"
            if f["confidence"]:
                confidence += f" ({f['confidence']})"
            url_short = f["url"]
            if len(url_short) > 40:
                # truncate for table
                url_short = url_short[:37] + "..."
            finding_id = f["id"] if f["id"] else "-"
            lines.append(f"| {title} | {finding_id} | {sev_display} | {f['vuln_type']} | `{url_short}` | {confidence} | {f['source']} |")
        lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション8: 次回推奨シナリオ
    # ------------------------------------------------------------------

    def _section_8_recommended_scenarios(self) -> str:
        lines: List[str] = []
        lines.append("## 8. 次回推奨シナリオ")
        lines.append("")

        # scenario_coverage から (context 内またはトップレベル)
        scenario_coverage = self._safe_dict(self._safe_get(self._session, "context", "scenario_coverage"))
        if not scenario_coverage:
            scenario_coverage = self._safe_dict(self._session.get("scenario_coverage", {}))

        missing_scenarios = self._safe_list(scenario_coverage.get("missing_scenarios", []))
        coverage_items = self._safe_list(scenario_coverage.get("coverage_items", []))

        # coverage_gate から
        coverage_gate = self._safe_dict(self._safe_get(self._session, "context", "coverage_gate"))
        if not coverage_gate:
            coverage_gate = self._safe_dict(self._session.get("coverage_gate", {}))

        missing_families = self._safe_list(coverage_gate.get("missing_families", []))

        has_recommendations = False

        # 未カバーのシナリオ
        uncovered_items = [item for item in coverage_items if isinstance(item, dict) and not bool(item.get("covered", False))]

        if uncovered_items or missing_scenarios or missing_families:
            has_recommendations = True

        reason_map = {
            "scn_01_idor_bola_object_access": "オブジェクトレベル認可の検証が未実施",
            "scn_02_mass_assignment_object_update": "マスアサインメント脆弱性の検証が未実施",
            "scn_03_privilege_escalation": "権限昇格の検証が未実施",
            "scn_04_endpoint_enumeration_bfla": "エンドポイント列挙/BFLAの検証が未実施",
            "scn_05_rate_limiting_abuse": "レート制限の検証が未実施",
            "scn_06_input_validation_injection": "入力検証/インジェクションの検証が未実施",
            "scn_07_token_trust_boundary": "トークン信頼境界の検証が未実施",
            "scn_08_oob_external_channel_flow": "OOB/外部チャネルフローの検証が未実施",
            "scn_09_multi_step_state_machine": "マルチステップ状態遷移の検証が未実施",
            "scn_10_semantic_business_logic": "ビジネスロジックの検証が未実施",
            "scn_11_multi_vector_chain": "複合ベクトルチェーンの検証が未実施",
            "scn_12_advanced_ssrf_internal_topology": "SSRF内部トポロジの検証が未実施",
        }

        seen_ids: set = set()

        if uncovered_items:
            lines.append("### 未カバーシナリオ（次回推奨）")
            lines.append("")
            lines.append("| シナリオID | 名称 | 推奨理由 |")
            lines.append("|------------|------|----------|")

            for item in uncovered_items:
                sid = self._safe_str(item.get("scenario_id", ""))
                if sid in seen_ids:
                    continue
                seen_ids.add(sid)
                title = self._safe_str(item.get("title", sid))
                reason = reason_map.get(sid, "カバレッジ未到達")
                lines.append(f"| {sid} | {title} | {reason} |")

        # missing_scenarios (文字列リスト)
        if missing_scenarios:
            for ms in missing_scenarios:
                if isinstance(ms, dict):
                    sid = self._safe_str(ms.get("scenario_id", ms.get("id", "")))
                elif isinstance(ms, str):
                    sid = ms
                else:
                    continue
                if sid in seen_ids:
                    continue
                seen_ids.add(sid)

                if isinstance(ms, dict):
                    title = self._safe_str(ms.get("title", sid))
                    reason = self._safe_str(ms.get("reason", "カバレッジ未到達"))
                    lines.append(f"| {sid} | {title} | {reason} |")
                else:
                    reason = reason_map.get(ms, "カバレッジ未到達")
                    lines.append(f"| {ms} | - | {reason} |")

        # missing_families
        if missing_families:
            if uncovered_items or missing_scenarios:
                lines.append("")

            lines.append("### 未カバー脆弱性ファミリー")
            lines.append("")
            lines.append("| 脆弱性ファミリー | 推奨理由 |")
            lines.append("|------------------|----------|")
            for mf in missing_families:
                if isinstance(mf, dict):
                    family = self._safe_str(mf.get("family", mf.get("name", "")))
                    reason = self._safe_str(mf.get("reason", "ファミリーカバレッジ未到達"))
                    lines.append(f"| {family} | {reason} |")
                elif isinstance(mf, str):
                    lines.append(f"| {mf} | ファミリーカバレッジ未到達 |")

        if not has_recommendations:
            lines.append("すべてのシナリオがカバーされています")

        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # セクション9: 未検証領域
    # ------------------------------------------------------------------

    def _section_9_unverified_areas(self) -> str:
        lines: List[str] = []
        lines.append("## 9. 未検証領域")
        lines.append("")

        has_data = False

        # scenario_coverage の missing_scenarios
        scenario_coverage = self._safe_dict(self._safe_get(self._session, "context", "scenario_coverage"))
        if not scenario_coverage:
            scenario_coverage = self._safe_dict(self._session.get("scenario_coverage", {}))

        missing_scenarios = self._safe_list(scenario_coverage.get("missing_scenarios", []))
        coverage_items = self._safe_list(scenario_coverage.get("coverage_items", []))
        uncovered_items = [item for item in coverage_items if isinstance(item, dict) and not bool(item.get("covered", False))]

        # 未カバーシナリオ
        all_missing_sc = set()
        for ms in missing_scenarios:
            if isinstance(ms, str):
                all_missing_sc.add(ms)
            elif isinstance(ms, dict):
                sid = self._safe_str(ms.get("scenario_id", ms.get("id", "")))
                if sid:
                    all_missing_sc.add(sid)
        for item in uncovered_items:
            sid = self._safe_str(item.get("scenario_id", ""))
            if sid:
                all_missing_sc.add(sid)

        if all_missing_sc:
            lines.append("### 未実施シナリオ")
            lines.append("")
            sc_list = sorted(all_missing_sc)
            for sc in sc_list:
                lines.append(f"- {sc}")
            lines.append(f"  - source: scenario_coverage.missing_scenarios + coverage_items (未カバー)")
            has_data = True
            lines.append("")

        # coverage_gate の missing_families
        coverage_gate = self._safe_dict(self._safe_get(self._session, "context", "coverage_gate"))
        if not coverage_gate:
            coverage_gate = self._safe_dict(self._session.get("coverage_gate", {}))

        missing_families = self._safe_list(coverage_gate.get("missing_families", []))
        all_missing_fam: set = set()
        for mf in missing_families:
            if isinstance(mf, str):
                all_missing_fam.add(mf)
            elif isinstance(mf, dict):
                fam = self._safe_str(mf.get("family", mf.get("name", "")))
                if fam:
                    all_missing_fam.add(fam)

        if all_missing_fam:
            lines.append("### 未カバー脆弱性ファミリー")
            lines.append("")
            fam_list = sorted(all_missing_fam)
            for fam in fam_list:
                lines.append(f"- {fam}")
            lines.append(f"  - source: coverage_gate.missing_families")
            has_data = True
            lines.append("")

        # pending_hitl
        pending_hitl = self._safe_list(self._safe_get(self._session, "context", "pending_hitl", default=[]))
        if pending_hitl:
            lines.append("### 保留中HITL項目")
            lines.append("")
            for item in pending_hitl:
                if isinstance(item, dict):
                    title = self._safe_str(item.get("title", item.get("name", item.get("id", ""))))
                    desc = self._safe_str(item.get("description", item.get("summary", "")))
                    lines.append(f"- {title}")
                    if desc:
                        lines.append(f"  - {desc}")
                elif isinstance(item, str):
                    lines.append(f"- {item}")
            lines.append(f"  - source: context.pending_hitl")
            has_data = True
            lines.append("")

        # decision_traces からスキップされた領域
        decision_traces = self._safe_list(self._session.get("decision_traces", []))
        skipped: List[str] = []
        for dt in decision_traces:
            if not isinstance(dt, dict):
                continue
            action = self._safe_str(dt.get("action", dt.get("decision", "")))
            if action.lower() in ("skip", "skipped", "defer", "deferred", "postpone"):
                reason = self._safe_str(dt.get("reason", dt.get("note", "")))
                target = self._safe_str(dt.get("target", dt.get("url", dt.get("scenario", ""))))
                entry = target or reason or action
                if entry and entry not in skipped:
                    skipped.append(entry)

        if skipped:
            lines.append("### スキップされた領域（decision_traces）")
            lines.append("")
            for s in skipped:
                lines.append(f"- {s}")
            lines.append(f"  - source: decision_traces")
            has_data = True
            lines.append("")

        if not has_data:
            lines.append("未検証領域なし")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # メインメソッド
    # ------------------------------------------------------------------

    def format(self, session_data: dict) -> str:
        """セッションJSONデータを受け取り、日本語Markdownレポート文字列を返す。

        Args:
            session_data: セッションJSONデータ（辞書）

        Returns:
            日本語Markdown形式の target_profile.md レポート文字列
        """
        self._session = session_data if isinstance(session_data, dict) else {}

        session_id = (
            self._safe_str(self._session.get("session_id", ""))
            or self._safe_str(self._safe_get(self._session, "context", "session_id", ""))
            or "unknown"
        )
        generated = self._now_jst()

        lines: List[str] = []
        lines.append("# ターゲットプロファイルレポート")
        lines.append("")
        lines.append(f"**セッションID:** `{session_id}`")
        lines.append(f"**生成日時:** {generated.strftime('%Y-%m-%d %H:%M:%S')} JST")
        lines.append(f"**生成ツール:** SHIGOKU - Target Profile Formatter")
        lines.append("")

        # セクション1-9 を順に生成
        lines.append(self._section_1_target_overview())
        lines.append(self._section_2_discovered_features())
        lines.append(self._section_3_tech_stack())
        lines.append(self._section_4_auth_mechanisms())
        lines.append(self._section_5_url_statistics())
        lines.append(self._section_6_attack_surface())
        lines.append(self._section_7_findings_list())
        lines.append(self._section_8_recommended_scenarios())
        lines.append(self._section_9_unverified_areas())

        return "\n".join(lines)


def generate_target_profile(
    session_data: Dict[str, Any],
) -> str:
    """セッションJSONデータから target_profile.md レポートを生成する便利関数。

    Args:
        session_data: セッションJSONデータ（辞書）

    Returns:
        日本語Markdown形式のレポート文字列
    """
    formatter = TargetProfileFormatter()
    return formatter.format(session_data)
