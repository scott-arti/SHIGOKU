
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

def repair_truncated_json(content: str) -> str:
    """
    途中で切断されたJSONを、閉じタグを補完することで可能な限り修復する。
    
    Args:
        content: 破損したJSON文字列
    
    Returns:
        修復されたJSON文字列
    """
    content = content.strip()
    if not content:
        return "{}"
        
    stack = []
    in_string = False
    escape = False
    
    last_valid_index = -1
    
    for i, char in enumerate(content):
        if escape:
            escape = False
            continue
        if char == '\\':
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
            
        if not in_string:
            if char in '{[':
                stack.append('}' if char == '{' else ']')
            elif char in '}]':
                if stack and stack[-1] == char:
                    stack.pop()
                else:
                    # 不正な閉じタグの場合はそこまでで切る
                    break
        
        last_valid_index = i

    # 有効な部分まで切り出し
    repaired = content[:last_valid_index + 1]
    
    # 進行中の文字列を閉じる
    if in_string:
        repaired += '"'
        
    # スタックに残っている閉じタグを逆順に補完
    while stack:
        repaired += stack.pop()
        
    return repaired

def safe_json_loads(content: str, default: Optional[Any] = None, context: str = "", attempt_repair: bool = True) -> Any:
    """
    安全なJSONパース（自動修復機能付き）
    
    Args:
        content: JSON文字列
        default: パース失敗時のデフォルト値 (Noneの場合は空dict)
        context: ログ用のコンテキスト情報
        attempt_repair: 修復を試みるかどうか
    
    Returns:
        パースされたオブジェクト、またはデフォルト値
    """
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        if attempt_repair:
            ctx_msg = f" ({context})" if context else ""
            logger.warning(f"JSON corrupted, attempting repair{ctx_msg}: {e}")
            try:
                repaired = repair_truncated_json(content)
                return json.loads(repaired)
            except Exception as repair_err:
                logger.error(f"JSON repair failed: {repair_err}")
        
        ctx_msg = f" ({context})" if context else ""
        logger.error(f"JSON parse error{ctx_msg}: {e}")
        return default if default is not None else {}

def robust_json_loads(content: str) -> list[Any]:
    """
    複数オブジェクト、JSONL、ゴミ混じりのJSONを極限まで読み込む。
    
    Args:
        content: パース対象の文字列
        
    Returns:
        パースできた全オブジェクトのリスト
    """
    results = []
    content = content.strip()
    if not content:
        return results
        
    # 1. まず全体を単一のJSON（またはリスト）として試行
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        return [data]
    except json.JSONDecodeError:
        pass
        
    # 2. 手動で全オブジェクトを抽出（Extra data / concatenated objects 対策）
    decoder = json.JSONDecoder()
    pos = 0
    content_len = len(content)
    
    while pos < content_len:
        # 次のオブジェクトの開始位置を探す
        start_brace = content.find('{', pos)
        start_bracket = content.find('[', pos)
        
        if start_brace == -1 and start_bracket == -1:
            break
            
        if start_brace == -1:
            start = start_bracket
        elif start_bracket == -1:
            start = start_brace
        else:
            start = min(start_brace, start_bracket)
            
        try:
            obj, next_pos = decoder.raw_decode(content, start)
            if isinstance(obj, list):
                results.extend(obj)
            else:
                results.append(obj)
            # 正常に読み込めたら位置を更新
            pos = next_pos
        except json.JSONDecodeError:
            # パース失敗時は1文字進めて再試行
            pos = start + 1
            
    return results

def stream_jsonl(file_path: str, robust: bool = True):
    """
    JSONLファイルをストリーミング形式で読み込み、1行ずつパースして返す（メモリ効率化）。
    
    Args:
        file_path: 対象ファイルパス
        robust: 破損データに対して堅牢なパースを試みるか
        
    Yields:
        パースされたオブジェクト
    """
    import os
    if not os.path.exists(file_path):
        return

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            if robust:
                # 堅牢なパース
                objs = robust_json_loads(line)
                for obj in objs:
                    yield obj
            else:
                # 高速な標準パース
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
