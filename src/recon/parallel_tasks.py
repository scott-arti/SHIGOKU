"""
並行タスク実装

Recon Pipeline の並行タスク（Full Port Scan, Visual Recon, Permutation, Dead Sub Scan）を実装する。
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any
from datetime import datetime

from src.recon.tool_runner import ToolRunner
from src.core.notifications.notifier import get_notifier
try:
    from src.core.engine.master_conductor import Task
except ImportError:
    Task = Any  # テスト用ダミー
from src.config import settings

logger = logging.getLogger(__name__)


class ParallelTasks:
    """並行タスクの実装
    
    各タスクは完了次第、分類→PM保存→MC返却を独立実行する。
    """
    
    def __init__(self, config: dict[str, Any], project_manager: Any, master_conductor: Any = None):
        """初期化
        
        Args:
            config: 設定辞書
            project_manager: ProjectManager インスタンス
            master_conductor: MasterConductor インスタンス
        """
        self.config = config
        self.pm = project_manager
        self.mc = master_conductor
        self.runner = ToolRunner()

    def _get_path(self, workspace: Path, state: Any, type_name: str, ext: str = "") -> Path:
        """命名規則に従ったファイルパスを取得する
        形式: YYYYMMDD_<project_name>_<type_name>[.ext]
        """
        date_str = datetime.now().strftime("%Y%m%d")
        project = "recon"
        if state and hasattr(state, "project_name") and state.project_name:
            project = state.project_name.replace(".", "_")
        elif isinstance(state, str) and state:
            project = state.replace(".", "_")
            
        filename = f"{date_str}_{project}_{type_name}"
        
        # Use ProjectManager structure if workspace matches project_dir
        # Note: workspace is passed from pipeline, which we just updated to be project_dir
        # We can also check self.pm explicitly
        if self.pm and hasattr(self.pm, "project_dir") and workspace == self.pm.project_dir:
            raw_dir = self.pm.project_dir / "scans" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            if ext:
                return raw_dir / f"{filename}.{ext}"
            return raw_dir / filename

        if ext:
            return workspace / f"{filename}.{ext}"
        return workspace / filename
    
    async def full_port_scan(
        self,
        live_subs: list[str],
        workspace: Path,
        state: Any,
    ) -> dict[str, Any]:
        """Full Port Scan タスク
        
        65535 全ポートスキャン。新ポート発見時は MC にタスク登録。
        
        Args:
            live_subs: ライブサブドメインのリスト
            workspace: ワークスペースディレクトリ
            state: ReconState インスタンス
        
        Returns:
            タスク結果
        """
        logger.info("Full Port Scan started: %d hosts", len(live_subs))
        task_name = "full_port_scan"
        
        if not live_subs:
            logger.warning("No live subdomains for Full Port Scan")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="no_live_subs")
            return {"status": "skipped", "reason": "no_live_subs"}
        
        # 入力ファイル作成
        input_file = self._get_path(workspace, state, "live_subdomains", "txt")
        input_file.write_text("\n".join(live_subs))
        
        # 出力ファイル
        output_file = self._get_path(workspace, state, "full_port_scan", "txt")
        
        # Top 20 ポートを除外
        top_20 = self.config.get("recon", {}).get("naabu_top_ports", "21,22,23,25,53,80,110,443,8080")
        
        # レート制限（攻撃フェーズ中はスロットル）
        rate = 100 if state.attack_phase_active else 1000
        
        # タイムアウト（サブドメイン数 × 10分）
        timeout_minutes = len(live_subs) * 10
        timeout_seconds = timeout_minutes * 60
        
        # naabu 実行
        if not self.runner.is_tool_available("naabu"):
            logger.warning(
                "naabu not found. Skipping Full Port Scan. "
                "If you are using Docker, please ensure naabu is installed in the container."
            )
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="tool_not_found")
            return {"status": "skipped", "reason": "tool_not_found", "tool": "naabu"}

        cmd = [
            "naabu",
            "-l", str(input_file),
            "-p", "-",  # 全ポート
            "-exclude-ports", top_20,
            "-rate", str(rate),
            "-t", str(getattr(settings, "max_concurrent_tasks", 10)),  # Add threads based on config
            "-o", str(output_file),
            "-silent",
        ]
        
        try:
            logger.info("Running: %s (timeout=%dm)", " ".join(cmd), timeout_minutes)
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                _, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning("Full Port Scan timed out after %dm. Processing partial results.", timeout_minutes)
                proc.kill()
                await proc.wait()
        
        except OSError as e:
            logger.error("Full Port Scan failed: %s", e)
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "failed", error_summary=str(e))
            return {"status": "error", "error": str(e)}

        # 結果パース
        if not output_file.exists():
            logger.warning("Full Port Scan output file not found")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "completed", resume_reason="no_output_file")
            return {"status": "no_results"}
        
        ports_found = output_file.read_text().strip().split("\n") if output_file.stat().st_size > 0 else []
        count = len(ports_found)
        logger.info("Full Port Scan completed: %d ports found", count)
        
        # Notify 送信
        try:
            notifier = get_notifier()
            if notifier:
                notifier.notify(
                    f"✅ **Full Port Scan Completed**\n"
                    f"Found **{count}** open ports/services across {len(live_subs)} targets.\n"
                    f"Output: `{output_file.name}`"
                )
        except Exception as e:
            logger.warning("Failed to send notification: %s", e)
        
        # MC にタスク登録（脆弱性スキャンなど）
        if self.mc and count > 0:
            try:
                # サービス発見をトリガーにした汎用タスクを追加
                task = Task(
                    id=f"analyze_services_{state.current_step}",
                    name="Analyze Discovered Services",
                    agent_type="vuln_scanner",  # 仮
                    action="scan_services",
                    params={
                        "services_file": str(output_file),
                        "target": state.target
                    },
                    priority=60
                )
                # _add_tasks は internal だが現状の I/F ではこれを使う必要がある
                if hasattr(self.mc, "_add_tasks"):
                    self.mc._add_tasks([task], source="recon.full_port_scan")
                    logger.info("Registered analysis task to MC")
            except Exception as e:
                logger.error("Failed to register task to MC: %s", e)
        
        # Checkpoint: record completed with artifact refs
        if state and hasattr(state, "update_parallel_task_progress"):
            artifact_refs = []
            if output_file.exists():
                artifact_refs.append({
                    "path": str(output_file),
                    "kind": "output",
                    "size": output_file.stat().st_size,
                    "mtime": output_file.stat().st_mtime,
                })
            state.update_parallel_task_progress(
                task_name, "completed", artifact_refs=artifact_refs,
            )
        
        return {
            "status": "completed",
            "ports_count": len(ports_found),
            "output_file": str(output_file),
        }
    
    async def visual_recon(
        self,
        live_subs: list[str],
        workspace: Path,
        state: Any = None,
    ) -> dict[str, Any]:
        """Visual Recon タスク
        
        gowitness でスクリーンショット取得。完了時に Notify で通知。
        
        Args:
            live_subs: ライブサブドメインのリスト
            workspace: ワークスペースディレクトリ
            state: ReconState インスタンス (optional, for checkpoint)
        
        Returns:
            タスク結果
        """
        logger.info("Visual Recon started: %d hosts", len(live_subs))
        task_name = "visual_recon"
        
        if not live_subs:
            logger.warning("No live subdomains for Visual Recon")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="no_live_subs")
            return {"status": "skipped", "reason": "no_live_subs"}
        
        # 入力ファイル作成
        # visual_recon は state を受け取っていないため、project_name は "recon" または workspace から推測
        # ここでは暫定的に "recon" を使用し、必要なら共通 I/F を検討
        input_file = self._get_path(workspace, "recon", "live_subdomains", "txt")
        input_file.write_text("\n".join(live_subs))
        
        # 出力ディレクトリ
        screenshots_dir = self._get_path(workspace, "recon", "screenshots")
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        
        # gowitness 実行
        if not self.runner.is_tool_available("gowitness"):
            logger.warning(
                "gowitness not found. Skipping Visual Recon. "
                "If you are using Docker, please ensure gowitness is installed in the container."
            )
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="tool_not_found")
            return {"status": "skipped", "reason": "tool_not_found", "tool": "gowitness"}

        cmd = [
            "gowitness",
            "file",
            "-f", str(input_file),
            "-P", str(screenshots_dir),
            "--timeout", "10",
        ]
        
        try:
            logger.info("Running: %s", " ".join(cmd))
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            _, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=1200,  # 20分
            )
        
        except asyncio.TimeoutError:
            logger.warning("Visual Recon timed out")
            proc.kill()
            await proc.wait()
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "failed", error_summary="timeout")
            return {"status": "timeout"}
        
        except OSError as e:
            logger.error("Visual Recon failed: %s", e)
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "failed", error_summary=str(e))
            return {"status": "error", "error": str(e)}
        
        # スクリーンショット数をカウント
        screenshot_count = len(list(screenshots_dir.glob("*.png")))
        logger.info("Visual Recon completed: %d screenshots", screenshot_count)
        
        # Notify 送信
        try:
            notifier = get_notifier()
            if notifier and screenshot_count > 0:
                notifier.notify(
                    f"📸 **Visual Recon Completed**\n"
                    f"Captured **{screenshot_count}** screenshots.\n"
                    f"Path: `{screenshots_dir}`"
                )
        except Exception as e:
            logger.warning("Failed to send notification: %s", e)

        # Checkpoint: record completed with artifact refs
        if state and hasattr(state, "update_parallel_task_progress"):
            artifact_refs = [{
                "path": str(screenshots_dir),
                "kind": "screenshots_dir",
                "size": 0,
                "mtime": screenshots_dir.stat().st_mtime if screenshots_dir.exists() else 0,
            }]
            state.update_parallel_task_progress(
                task_name, "completed", artifact_refs=artifact_refs,
            )
        
        return {
            "status": "completed",
            "screenshot_count": screenshot_count,
            "screenshots_dir": str(screenshots_dir),
        }
    
    async def permutation_scan(
        self,
        all_subs: list[str],
        target: str,
        workspace: Path,
        state: Any,
    ) -> dict[str, Any]:
        """Permutation Scanning タスク
        
        LLM + alterx で候補生成、shuffledns で DNS 解決。
        無限ループ防止のため、一度だけ実行。
        
        Args:
            all_subs: 全サブドメインのリスト
            target: ターゲットドメイン (例: "example.com")
            workspace: ワークスペースディレクトリ
            state: ReconState インスタンス
        
        Returns:
            タスク結果
        """
        logger.info("Permutation Scan started")
        task_name = "permutation_scan"
        
        # 無限ループ防止ガード
        if state.permutation_executed:
            logger.warning("Permutation already executed. Skipping.")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="already_executed")
            return {"status": "skipped", "reason": "already_executed"}
        
        if not all_subs:
            logger.warning("No subdomains for Permutation Scan")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="no_subdomains")
            return {"status": "skipped", "reason": "no_subdomains"}
        
        # Step 1: LLM による候補生成
        llm_candidates = []
        if self.mc and self.mc.llm_client:
            try:
                # 既存サブドメインからパターンを学習して候補を生成
                sample_subs = sorted(all_subs)[:50]  # 学習用サンプル
                prompt = (
                    f"Generate 50 potential subdomains for '{target}' "
                    f"based on these existing ones: {', '.join(sample_subs)}. "
                    "Output only the subdomains, one per line."
                )
                
                logger.info("Requesting LLM to generate subdomain candidates...")
                from src.core.models.llm import LLMClient
                llm_model = LLMClient(role="specialist_light").model
                response = self.mc.llm_client.chat.completions.create(
                    model=llm_model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=500,
                )
                
                content = response.choices[0].message.content
                if content:
                    llm_candidates = [
                        line.strip() for line in content.splitlines() 
                        if line.strip() and target in line
                    ]
                    logger.info("LLM generated %d candidates", len(llm_candidates))
            except Exception as e:
                logger.warning("LLM generation failed: %s", e)

        llm_candidates_file = self._get_path(workspace, state, "llm_candidates", "txt")
        llm_candidates_file.write_text("\n".join(llm_candidates) if llm_candidates else "")
        
        # Step 2: alterx による展開
        if not self.runner.is_tool_available("alterx"):
            logger.warning(
                "alterx not found. Skipping Permutation Scan. "
                "If you are using Docker, please ensure alterx is installed in the container."
            )
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="tool_not_found")
            return {"status": "skipped", "reason": "tool_not_found", "tool": "alterx"}

        all_subs_file = self._get_path(workspace, state, "all_subdomains", "txt")
        all_subs_file.write_text("\n".join(all_subs))
        
        alterx_output = self._get_path(workspace, state, "alterx_candidates", "txt")
        
        cmd_alterx = [
            "alterx",
            "-l", str(all_subs_file),
            "-o", str(alterx_output),
        ]
        
        try:
            logger.info("Running alterx: %s", " ".join(cmd_alterx))
            proc = await asyncio.create_subprocess_exec(
                *cmd_alterx,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        except OSError as e:
            logger.error("alterx failed: %s", e)
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "failed", error_summary=str(e))
            return {"status": "error", "error": str(e)}
        
        # Step 3: 候補を統合
        permutation_input = self._get_path(workspace, state, "permutation_input", "txt")
        
        candidates = set()
        if llm_candidates_file.exists():
            candidates.update(llm_candidates_file.read_text().strip().split("\n"))
        if alterx_output.exists():
            candidates.update(alterx_output.read_text().strip().split("\n"))
        
        candidates = [c for c in candidates if c]  # 空文字列を除外
        
        if not candidates:
            logger.warning("No permutation candidates generated")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="no_candidates")
            return {"status": "no_candidates"}
        
        permutation_input.write_text("\n".join(sorted(candidates)))
        logger.info("Generated %d permutation candidates", len(candidates))
        
        # Step 4: shuffledns で DNS 解決
        if not self.runner.is_tool_available("shuffledns"):
            logger.warning(
                "shuffledns not found. Skipping DNS resolution in Permutation Scan. "
                "If you are using Docker, please ensure shuffledns is installed in the container."
            )
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="tool_not_found")
            return {"status": "skipped", "reason": "tool_not_found", "tool": "shuffledns"}

        # リゾルバーは簡易的に Google DNS を使用（Phase 5 で動的取得実装）
        resolvers_file = self._get_path(workspace, state, "resolvers", "txt")
        resolvers_file.write_text("8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n")
        
        permutation_resolved = self._get_path(workspace, state, "permutation_resolved", "txt")
        
        # タイムアウト: 候補数 / 10000 分（最低15分）
        timeout_minutes = max(15, len(candidates) // 10000)
        timeout_seconds = timeout_minutes * 60
        
        cmd_shuffledns = [
            "shuffledns",
            "-d", target,
            "-w", str(permutation_input),
            "-r", str(resolvers_file),
            "-o", str(permutation_resolved),
            "-t", "100",
        ]
        
        try:
            logger.info("Running shuffledns: %s (timeout=%dm)", " ".join(cmd_shuffledns), timeout_minutes)
            proc = await asyncio.create_subprocess_exec(
                *cmd_shuffledns,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                _, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning("shuffledns timed out after %dm", timeout_minutes)
                proc.kill()
                await proc.wait()
        
        except OSError as e:
            logger.error("shuffledns failed: %s", e)
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "failed", error_summary=str(e))
            return {"status": "error", "error": str(e)}
        
        # Step 5: 新サブドメインを抽出
        if not permutation_resolved.exists():
            logger.warning("No permutation results")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "completed", resume_reason="no_results")
            return {"status": "no_results"}
        
        resolved_subs = permutation_resolved.read_text().strip().split("\n") if permutation_resolved.stat().st_size > 0 else []
        new_subs = set(resolved_subs) - set(all_subs)
        
        new_subs_file = self._get_path(workspace, state, "new_subdomains", "txt")
        new_subs_file.write_text("\n".join(sorted(new_subs)))
        
        logger.info("Permutation Scan completed: %d new subdomains found", len(new_subs))
        
        # フラグを設定して無限ループを防止
        state.permutation_executed = True
        
        # Notify 送信
        try:
            notifier = get_notifier()
            if notifier and len(new_subs) > 0:
                notifier.notify(
                    f"🧬 **Permutation Scan Completed**\n"
                    f"Found **{len(new_subs)}** new subdomains.\n"
                    f"Candidates: {len(candidates)}, Resolved: {len(resolved_subs)}"
                )
        except Exception as e:
            logger.warning("Failed to send notification: %s", e)
        
        # MC にタスク登録
        if self.mc and len(new_subs) > 0 and hasattr(self.mc, "_add_tasks"):
            try:
                # 新規サブドメインに対してポートスキャンタスクを追加
                task = Task(
                    id=f"scan_new_subs_{state.current_step}",
                    name=f"Scan New Subdomains ({len(new_subs)})",
                    agent_type="recon_master", # または適切なエージェント
                    action="port_scan",
                    params={
                        "targets": list(new_subs),
                        "mode": "fast"
                    },
                    priority=70
                )
                self.mc._add_tasks([task], source="recon.permutation")
            except Exception as e:
                logger.error("Failed to register task to MC: %s", e)
        
        # Checkpoint: record completed with artifact refs
        if state and hasattr(state, "update_parallel_task_progress"):
            artifact_refs = []
            for ref_file, kind in [
                (new_subs_file, "new_subs"),
                (permutation_resolved, "resolved"),
            ]:
                if ref_file.exists():
                    artifact_refs.append({
                        "path": str(ref_file),
                        "kind": kind,
                        "size": ref_file.stat().st_size,
                        "mtime": ref_file.stat().st_mtime,
                    })
            state.update_parallel_task_progress(
                task_name, "completed", artifact_refs=artifact_refs,
            )
        
        return {
            "status": "completed",
            "candidates_count": len(candidates),
            "resolved_count": len(resolved_subs),
            "new_subs_count": len(new_subs),
            "new_subs_file": str(new_subs_file),
        }
    
    async def dead_subdomain_scan(
        self,
        all_subs: list[str],
        live_subs: list[str],
        workspace: Path,
        state: Any,
    ) -> dict[str, Any]:
        """Dead Subdomain Scan タスク
        
        Dead サブドメインの全ポートスキャンで隠れたサービスを発見。
        Full Port Scan の完了後に実行される。
        
        Args:
            all_subs: 全サブドメインのリスト
            live_subs: ライブサブドメインのリスト
            workspace: ワークスペースディレクトリ
            state: ReconState インスタンス
        
        Returns:
            タスク結果
        """
        logger.info("Dead Subdomain Scan started")
        task_name = "dead_subdomain_scan"
        
        # Dead サブドメインを抽出
        dead_subs = list(set(all_subs) - set(live_subs))
        
        if not dead_subs:
            logger.info("No dead subdomains to scan")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="no_dead_subs")
            return {"status": "skipped", "reason": "no_dead_subs"}
        
        # 入力ファイル作成
        dead_subs_file = self._get_path(workspace, state, "dead_subdomains", "txt")
        dead_subs_file.write_text("\n".join(dead_subs))
        
        # 出力ファイル
        output_file = self._get_path(workspace, state, "dead_subdomain_scan", "txt")
        
        # レート制限（攻撃フェーズ中はスロットル）
        rate = 100 if state.attack_phase_active else 1000
        
        # タイムアウト（Dead サブドメイン数 × 10分）
        timeout_minutes = len(dead_subs) * 10
        timeout_seconds = timeout_minutes * 60
        
        # naabu 実行（全ポートスキャン）
        if not self.runner.is_tool_available("naabu"):
            logger.warning(
                "naabu not found. Skipping Dead Subdomain Scan. "
                "If you are using Docker, please ensure naabu is installed in the container."
            )
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "skipped", resume_reason="tool_not_found")
            return {"status": "skipped", "reason": "tool_not_found", "tool": "naabu"}

        cmd = [
            "naabu",
            "-l", str(dead_subs_file),
            "-p", "-",  # 全ポート
            "-rate", str(rate),
            "-t", str(getattr(settings, "max_concurrent_tasks", 10)),  # Add threads based on config
            "-o", str(output_file),
            "-silent",
        ]
        
        try:
            logger.info("Running: %s (timeout=%dm)", " ".join(cmd), timeout_minutes)
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                _, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_seconds,
                )
            except asyncio.TimeoutError:
                logger.warning("Dead Sub Scan timed out after %dm", timeout_minutes)
                proc.kill()
                await proc.wait()
        
        except OSError as e:
            logger.error("Dead Sub Scan failed: %s", e)
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "failed", error_summary=str(e))
            return {"status": "error", "error": str(e)}
        
        # 結果パース
        if not output_file.exists():
            logger.warning("Dead Sub Scan output file not found")
            if state and hasattr(state, "update_parallel_task_progress"):
                state.update_parallel_task_progress(task_name, "completed", resume_reason="no_output_file")
            return {"status": "no_results"}
        
        alive_count = len(output_file.read_text().strip().split("\n")) if output_file.stat().st_size > 0 else 0
        logger.info("Dead Sub Scan completed: %d dead subdomains revived", alive_count)
        
        # Notify 送信
        try:
            notifier = get_notifier()
            if notifier and alive_count > 0:
                notifier.notify(
                    f"🧟 **Dead Subdomain Scan Completed**\n"
                    f"Revived **{alive_count}** subdomains from {len(dead_subs)} dead targets.\n"
                    f"Output: `{output_file.name}`"
                )
        except Exception as e:
            logger.warning("Failed to send notification: %s", e)
        
        # MC にタスク登録
        if self.mc and alive_count > 0 and hasattr(self.mc, "_add_tasks"):
            try:
                # 復活したサブドメインの調査タスク
                task = Task(
                    id=f"investigate_revived_{state.current_step}",
                    name="Investigate Revived Subdomains",
                    agent_type="vuln_scanner",
                    action="scan_services",
                    params={
                        "services_file": str(output_file),
                        "target": state.target
                    },
                    priority=80
                )
                self.mc._add_tasks([task], source="recon.dead_sub_scan")
            except Exception as e:
                logger.error("Failed to register task to MC: %s", e)

        # Checkpoint: record completed with artifact refs
        if state and hasattr(state, "update_parallel_task_progress"):
            artifact_refs = []
            if output_file.exists():
                artifact_refs.append({
                    "path": str(output_file),
                    "kind": "output",
                    "size": output_file.stat().st_size,
                    "mtime": output_file.stat().st_mtime,
                })
            state.update_parallel_task_progress(
                task_name, "completed", artifact_refs=artifact_refs,
            )
        
        return {
            "status": "completed",
            "dead_subs_count": len(dead_subs),
            "revived_count": alive_count,
            "output_file": str(output_file),
        }
