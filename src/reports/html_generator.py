import json
import logging
from pathlib import Path
from typing import List, Any
from datetime import datetime
from src.core.utils.json_utils import safe_json_loads

logger = logging.getLogger(__name__)

class HTMLReportGenerator:
    """
    インタラクティブなHTMLレポートを生成するクラス。
    session_state.json のデータをテンプレートに埋め込んで単一のHTMLファイルを作成する。
    """
    
    def __init__(self, template_path: str = "src/reports/templates/dashboard.html"):
        self.template_path = Path(template_path)
        
    def generate(self, session_data: dict, history_data: List[dict] = None, output_path: str = None) -> str:
        """
        HTMLレポートを生成する
        
        Args:
            session_data: セッションデータ
            history_data: 過去のセッション履歴リスト
            output_path: 出力先パス (あればファイルに書き込む)
            
        Returns:
            生成されたHTML
        """
        try:
            with open(self.template_path, "r", encoding="utf-8") as f:
                template_content = f.read()
        except FileNotFoundError:
            logger.error("Template not found: %s", self.template_path)
            raise
        
        try:
            # 1. Session Data Injection
            json_str = json.dumps(session_data, default=str, ensure_ascii=False)
            import base64
            b64_str = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
            
            target_str = 'BASE64_DATA_PLACEHOLDER'
            if target_str in template_content:
                final_content = template_content.replace(target_str, b64_str)
            else:
                logger.warning("Placeholder '%s' not found in template. Appending data safely.", target_str)
                safe_json = json_str.replace("</script>", r"<\/script>")
                final_content = template_content.replace(
                    "</body>", 
                    f'<script id="session-data" type="application/json">{safe_json}</script></body>'
                )

            # 2. History Data Injection
            if history_data:
                hist_str = json.dumps(history_data, default=str, ensure_ascii=False)
                b64_hist = base64.b64encode(hist_str.encode("utf-8")).decode("ascii")
                
                hist_target = 'BASE64_HISTORY_PLACEHOLDER'
                if hist_target in final_content:
                    final_content = final_content.replace(hist_target, b64_hist)
                else:
                    # If placeholder doesn't exist, ignore (template might be old)
                    pass
            
        except Exception as e:
            logger.error("Failed to generate HTML report: %s", e)
            raise

        if output_path:
            out = Path(output_path)
            with open(out, "w", encoding="utf-8") as f:
                f.write(final_content)
            logger.info("Report generated: %s", output_path)
            
            # Docker環境での権限修正 (root -> uid 1000)
            import os
            if hasattr(os, 'chown') and os.geteuid() == 0:
                try:
                    os.chown(str(out), 1000, 1000)
                    logger.info("Changed ownership of %s to 1000:1000", extract_filename(output_path))
                except Exception as e:
                    logger.warning("Failed to change ownership: %s", e)
                    
        return final_content

def generate_report_from_file(session_file: str = "session_state.json") -> str:
    """
    指定されたセッションファイルからレポートを生成 (CLI/Debug用)
    
    Args:
        session_file: セッションファイルパス
        
    Returns:
        生成されたHTMLファイルのパス
    """
    path = Path(session_file)
    if not path.exists():
        logger.error("Session file not found: %s", session_file)
        return ""
        
    try:
        raw_text = path.read_text(encoding="utf-8")
        raw_data = safe_json_loads(raw_text, context=f"report_gen:{path.name}")
    except Exception as e:
        logger.error("Failed to read session file %s: %s", path.name, e)
        return ""
        
    # JS用にデータを整形
    tasks = raw_data.get("completed_tasks", [])
    pending = raw_data.get("task_queue", [])
    
    # 互換性のため、pendingタスクにstateがない場合は設定
    for t in pending:
        if "state" not in t:
            t["state"] = "pending"
            
    # Deduplicate: prioritized completed tasks
    completed_ids = {t["id"] for t in tasks}
    filtered_pending = [t for t in pending if t["id"] not in completed_ids]
    
    all_tasks = tasks + filtered_pending
    
    data_for_js = {
        "tasks": all_tasks,
        "timestamp": raw_data.get("start_time", 0)
    }
    
    # テンプレートのパス解決
    base_dir = Path(__file__).parent
    template_path = base_dir / "templates" / "dashboard.html"
    if not template_path.exists():
        template_path = Path("src/reports/templates/dashboard.html")
        
    generator = HTMLReportGenerator(template_path=str(template_path))
    
    # JSTタイムゾーン定義
    from datetime import timezone, timedelta
    JST_TZ = timezone(timedelta(hours=9))

    # Phase 1: Global History Collection
    # Structure: { "ProjectName": [ {filename, timestamp, mtime, active, session_path, report_path} ] }
    history_groups = {}
    
    try:
        # Determine Project Root
        project_root = None
        if path.parent.name == "sessions" and path.parent.parent.parent.name == "projects":
             project_root = path.parent.parent.parent
        elif path.parent.name == "sessions":
             if path.parent.parent.parent.name == "projects":
                 project_root = path.parent.parent.parent
        
        # Determine Current Project Name
        current_project_name = "Current Project"
        if path.parent.name == "sessions":
            current_project_name = path.parent.parent.name
        
        # Scan Targets
        scan_targets = []
        roots_to_check = []
        if project_root:
            roots_to_check.append(project_root)

        # 重複排除してスキャン
        seen_projects = set()
        for root in roots_to_check:
            if root.exists():
                for p_dir in root.iterdir():
                    if p_dir.is_dir():
                        sessions_dir = p_dir / "sessions"
                        if sessions_dir.exists():
                            target_key = (p_dir.name, str(sessions_dir))
                            if target_key not in seen_projects:
                                scan_targets.append((p_dir.name, sessions_dir))
                                seen_projects.add(target_key)
        
        if not scan_targets:
            scan_targets.append((current_project_name, path.parent))
            
        # Collect Data
        # Flattened list for generation phase: [{session_path, report_path, project_name}]
        generation_targets = []

        # Pre-load target session info for matching
        target_start_time = None
        try:
            with open(path, "r", encoding="utf-8") as Tf:
                t_data = json.load(Tf)
                target_start_time = t_data.get("start_time")
        except Exception as e:
            logger.warning("Failed to read target session for matching: %s", e)

        for p_name, s_dir in scan_targets:
            # Get existing history for this project name or start new
            project_history = history_groups.get(p_name, [])
            
            session_files = list(s_dir.glob("session_*.json"))
            # session_interrupted.json も含める
            if (s_dir / "session_interrupted.json").exists():
                session_files.append(s_dir / "session_interrupted.json")
            
            for p in session_files:
                # 重複回避 (同じファイル名が既にあればスキップ - 基本的にセッション名はユニーク)
                if any(h.get("name") == p.name for h in project_history):
                    continue

                # Name resolution
                out_name = p.with_suffix(".html").name
                if not out_name.startswith("report_") and out_name.startswith("session_"):
                    out_name = out_name.replace("session_", "report_")

                # Timestamp & Active Check
                p_start_time = None
                timestamp_str = ""
                try:
                    # Try reading for accurate matching (use repair-capable load)
                    raw_p = p.read_text(encoding="utf-8")
                    p_data = safe_json_loads(raw_p, context=f"history_match:{p.name}")
                    p_start_time = p_data.get("start_time")
                    
                    st_mtime = p.stat().st_mtime
                    dt_utc = datetime.fromtimestamp(st_mtime, tz=timezone.utc)
                    dt_jst = dt_utc.astimezone(JST_TZ)
                    timestamp_str = dt_jst.strftime("%Y-%m-%d %H:%M")
                except Exception:
                     # Fallback
                    timestamp_str = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                
                # Match by content(start_time) OR path(if exact same file)
                is_active = False
                if target_start_time and p_start_time:
                    is_active = (target_start_time == p_start_time)
                else:
                    is_active = (p.resolve() == path.resolve())
                
                # Report Path (Absolute)
                target_full_path = s_dir / out_name

                # Store for Generation Phase
                generation_targets.append({
                    "session_path": p,
                    "report_path": target_full_path,
                    "active": is_active
                })

                project_history.append({
                    "abs_path": target_full_path, # Temporary for calculation
                    "filename": "PLACEHOLDER",    # Will be replaced per-generation
                    "timestamp": timestamp_str,
                    "mtime": p.stat().st_mtime,
                    "active": is_active # "Active" means "This file". Will be updated per-generation.
                })
            
            # Update history group
            history_groups[p_name] = project_history

        # 全てのプロジェクトスキャン後に時間を基準にソート
        for grp in history_groups:
            history_groups[grp].sort(key=lambda x: x["mtime"], reverse=True)

    except Exception as e:
        logger.warning("Failed to collect global history: %s", e)
        # Continue with empty history logic if partial fail
        
    # Phase 2: Generate All Reports
    # Now we iterate through all sessions we found and regenerate their HTMLs with the FULL context.
    
    final_output_path = ""
    
    for target in generation_targets:
        session_p = target["session_path"]
        report_p = target["report_path"]
        
        # Determine if this is the "Main" request
        is_main_request = target["active"]
        if is_main_request:
            final_output_path = str(report_p)
            
        # Optimization: Skip if exists AND not main request AND file age is < 1 min?
        # User wants "Everywhere history". So we must update if history changed.
        # Just update all.
        
        try:
            # Prepare Custom History for THIS file
            # 1. Update relative paths
            # 2. Update 'active' flag
            
            custom_history = {}
            for grp_name, items in history_groups.items():
                new_items = []
                for item in items:
                    # Copy item to avoid mutating global
                    new_item = item.copy()
                    
                    # Relpath calculation
                    try:
                        import os
                        # Relpath from 'report_p.parent' to 'item["abs_path"]'
                        rel = os.path.relpath(item["abs_path"], start=report_p.parent)
                        new_item["filename"] = rel
                    except ValueError:
                        new_item["filename"] = str(item["abs_path"])
                    
                    # Active flag (is this line pointing to the file being generated?)
                    new_item["active"] = (item["abs_path"] == report_p)
                    
                    # Remove internal key
                    del new_item["abs_path"]
                    new_items.append(new_item)
                
                custom_history[grp_name] = new_items
                
            # Load Data
            try:
                raw_text = session_p.read_text(encoding="utf-8")
                data = safe_json_loads(raw_text, context=f"history_gen:{session_p.name}")
                if not data:
                    logger.warning("Session file essentially empty (repaired as {}): %s", session_p.name)
                    continue
            except Exception as e:
                logger.warning("Skipping session file in history due to error: %s (%s)", session_p.name, e)
                continue
                
            # Sanitize Data
            tasks = data.get("completed_tasks", [])
            pending = data.get("task_queue", [])
            for t in pending:
                 if "state" not in t: t["state"] = "pending"
            
            # Dedupe
            comp_ids = {t["id"] for t in tasks}
            filt_pending = [t for t in pending if t["id"] not in comp_ids]
            
            js_data = {
                "tasks": tasks + filt_pending,
                "timestamp": data.get("start_time", 0)
            }
            
            # Generate
            # Note: generator instance is reused, template cached?
            # Template read in .generate() every time? No, __init__ sets path, .generate() reads.
            # Performance OK.
            generator.generate(js_data, history_data=custom_history, output_path=str(report_p))
            
            if is_main_request:
                logger.info("Generated MAIN report: %s", report_p)
                
                # Update latest.html
                try:
                    import os
                    latest_link = report_p.parent / "latest.html"
                    # Remove existing if any
                    if latest_link.exists() or latest_link.is_symlink():
                        latest_link.unlink()
                    
                    # Create symlink relative to the directory
                    # latest.html -> report_XXXX.html
                    # target_name = report_p.name
                    # latest_link.symlink_to(target_name)
                    
                    # Symlink on Linux/Mac, Copy on Windows or fail safe
                    try:
                        os.symlink(report_p.name, latest_link)
                    except OSError:
                        # Fallback to copy if symlink fails
                        import shutil
                        shutil.copy2(report_p, latest_link)
                        
                    logger.info("Updated latest.html -> %s", report_p.name)
                except Exception as e:
                    logger.warning("Failed to update latest.html: %s", e)

            else:
                logger.debug("Backfilled/Updated report: %s", report_p)
                
        except Exception as e:
            logger.warning("Failed to generate report for %s: %s", session_p.name, e)

    return final_output_path

def extract_filename(path):
    return Path(path).name
