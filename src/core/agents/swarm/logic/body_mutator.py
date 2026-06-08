
import json
import logging
import copy
import re
import uuid
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import parse_qs, urlencode

logger = logging.getLogger(__name__)

class BodyMutator:
    """
    Content-Type に応じて Body を安全にパース・改変するユーティリティ。
    ステートレスな純粋関数のみを提供。
    """

    @staticmethod
    def detect_content_type(headers: Dict[str, str], body: Optional[str]) -> str:
        """
        Content-Type を判定。ヘッダ優先、なければ Body 内容からヒューリスティック推定。
        """
        if not body:
            return "unknown"

        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v # 値そのものを保持（boundaryの大小文字が重要なため）
                break
        
        ct_lower = ct.lower()
        if "application/json" in ct_lower:
            return "json"
        if "application/x-www-form-urlencoded" in ct_lower:
            return "urlencoded"
        if "multipart/form-data" in ct_lower:
            return ct # オリジナルの大文字小文字を維持した値を返す

        # 2. ヒューリスティック推定
        stripped_body = body.strip()
        if stripped_body.startswith(("{", "[")):
            return "json"
        if re.match(r'^[a-zA-Z0-9_\-\.]+=[^&]*(&[a-zA-Z0-9_\-\.]+=[^&]*)*$', stripped_body):
            return "urlencoded"
        if "--" in stripped_body and "Content-Disposition" in stripped_body:
            return "multipart/form-data"
            
        return "unknown"

    @staticmethod
    def _extract_boundary(content_type: str) -> Optional[str]:
        """Content-Type 文字列から boundary を抽出"""
        if "boundary=" in content_type:
            parts = content_type.split("boundary=")
            if len(parts) > 1:
                return parts[1].split(";")[0].strip('"')
        return None

    @staticmethod
    def parse(body: str, content_type: str, keep_list: bool = False) -> Dict[str, Any]:
        """Body を辞書型に変換"""
        if not body:
            return {}
            
        if content_type == "json":
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                logger.warning("Failed to parse JSON body")
                return {}
        elif content_type == "urlencoded":
            qs = parse_qs(body)
            if keep_list:
                return {k: v for k, v in qs.items()}
            # parse_qs は値をリストで返すため、単一値に平坦化
            return {k: v[0] if v else "" for k, v in qs.items()}
        elif "multipart/form-data" in content_type:
            boundary = BodyMutator._extract_boundary(content_type)
            if not boundary:
                # Body から推測
                match = re.search(r'^--([a-zA-Z0-9\'\(\)\+\_,\-\.\/:=\? ]+)', body)
                if match:
                    boundary = match.group(1)
            
            if not boundary:
                logger.warning("Multipart boundary not found")
                return {}

            parsed = {}
            # Boundary で分割
            parts = body.split(f"--{boundary}")
            for part in parts:
                part = part.strip()
                if not part or part == "--":
                    continue
                
                # ヘッダとボディを分離 (\r\n\r\n または \n\n)
                if "\r\n\r\n" in part:
                    h_block, b_block = part.split("\r\n\r\n", 1)
                elif "\n\n" in part:
                    h_block, b_block = part.split("\n\n", 1)
                else:
                    continue

                # name="xxx" を抽出
                name_match = re.search(r'name="([^"]+)"', h_block)
                if name_match:
                    name = name_match.group(1)
                    
                    # メタデータの抽出
                    filename_match = re.search(r'filename="([^"]+)"', h_block)
                    ct_match = re.search(r'Content-Type:\s*([^\r\n]+)', h_block, re.IGNORECASE)
                    
                    val = b_block.rstrip("\r\n").rstrip("\n")
                    
                    # データ構造の定義
                    item = {
                        "value": val,
                        "filename": filename_match.group(1) if filename_match else None,
                        "content_type": ct_match.group(1).strip() if ct_match else None,
                        "headers": h_block.strip() # 元のヘッダーブロックを保持（不明なヘッダーへの対応）
                    }
                    
                    if keep_list:
                        if name in parsed:
                            parsed[name].append(item)
                        else:
                            parsed[name] = [item]
                    else:
                        parsed[name] = item
            return parsed
        
        return {}

    @staticmethod
    def serialize(data: Dict[str, Any], content_type: str) -> str:
        """辞書型を Body 文字列に再変換"""
        if not data:
            return ""
            
        if content_type == "json":
            return json.dumps(data)
        elif content_type == "urlencoded":
            return urlencode(data, doseq=True)
        elif "multipart/form-data" in content_type:
            boundary = BodyMutator._extract_boundary(content_type) or "----ShigokuBoundary" + str(uuid.uuid4())[:8]
            lines = []
            for k, v in data.items():
                values = v if isinstance(v, list) else [v]
                for item in values:
                    lines.append(f"--{boundary}")
                    
                    # 拡張構造 (dict) か単純値か
                    if isinstance(item, dict) and "value" in item:
                        val = str(item["value"])
                        filename = item.get("filename")
                        content_type = item.get("content_type")
                        
                        disp = f'Content-Disposition: form-data; name="{k}"'
                        if filename:
                            disp += f'; filename="{filename}"'
                        lines.append(disp)
                        
                        if content_type:
                            lines.append(f"Content-Type: {content_type}")
                        
                        # その他のヘッダーがあれば（headers に含まれていないもの）
                        # 現状は簡易化のため上記のみ
                    else:
                        lines.append(f'Content-Disposition: form-data; name="{k}"')
                        val = str(item)
                        
                    lines.append("")
                    lines.append(val)
            
            if lines:
                lines.append(f"--{boundary}--")
                lines.append("") # 最後に改行
                return "\r\n".join(lines)
            return ""
            
        return ""

    @staticmethod
    def extract_ids(body: str, content_type: str) -> List[Tuple[str, str, str]]:
        """
        Body 内から ID/UUID を抽出。
        """
        data = BodyMutator.parse(body, content_type)
        if not data:
            return []

        uuid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

        def find_ids_recursive(obj):
            items = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (str, int)):
                        val_str = str(v)
                        if 'id' in k.lower() or 'uuid' in k.lower():
                            if re.match(r'^\d+$', val_str):
                                items.append((val_str, "numeric", "body"))
                            elif re.match(f'^{uuid_pattern}$', val_str):
                                items.append((val_str, "uuid", "body"))
                    elif isinstance(v, (dict, list)):
                        items.extend(find_ids_recursive(v))
            elif isinstance(obj, list):
                for item in obj:
                    items.extend(find_ids_recursive(item))
            return items

        return list(set(find_ids_recursive(data)))

    @staticmethod
    def replace_value(body: str, content_type: str, old_val: str, new_val: str) -> str:
        """
        特定の値を新しい値に置換。
        """
        if not body:
            return ""

        if content_type == "json":
            try:
                data = json.loads(body)
                def replace_recursive(obj):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            if str(v) == old_val and ('id' in k.lower() or 'uuid' in k.lower()):
                                try:
                                    obj[k] = type(v)(new_val)
                                except (ValueError, TypeError):
                                    obj[k] = new_val
                            elif isinstance(v, (dict, list)):
                                replace_recursive(v)
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj):
                            if str(item) == old_val:
                                try:
                                    obj[i] = type(item)(new_val)
                                except (ValueError, TypeError):
                                    obj[i] = new_val
                            elif isinstance(item, (dict, list)):
                                replace_recursive(item)
                
                new_data = copy.deepcopy(data)
                replace_recursive(new_data)
                return json.dumps(new_data)
            except json.JSONDecodeError:
                return body.replace(old_val, new_val)
        
        elif content_type == "urlencoded" or "multipart/form-data" in content_type:
            data = BodyMutator.parse(body, content_type, keep_list=True)
            new_data = {}
            for k, v in data.items():
                if isinstance(v, list):
                    processed_list = []
                    for item in v:
                        if isinstance(item, dict) and "value" in item:
                            if str(item["value"]) == old_val:
                                item["value"] = new_val
                            processed_list.append(item)
                        else:
                            processed_list.append(new_val if str(item) == old_val else item)
                    new_data[k] = processed_list
                else:
                    item = v
                    if isinstance(item, dict) and "value" in item:
                        if str(item["value"]) == old_val:
                            item["value"] = new_val
                        new_data[k] = item
                    else:
                        new_data[k] = new_val if str(item) == old_val else item
            return BodyMutator.serialize(new_data, content_type)

        return body.replace(old_val, new_val)

    @staticmethod
    def inject_properties(body: str, content_type: str, props: Dict[str, Any]) -> str:
        """
        特権プロパティを Body に注入。
        """
        data = BodyMutator.parse(body, content_type, keep_list=True)
        data.update(props)
        return BodyMutator.serialize(data, content_type)

    @staticmethod
    def duplicate_param(body: str, content_type: str, key_to_dup: str, new_val: Any) -> str:
        """
        HPP (HTTP Parameter Pollution) 用にパラメータを重複させる。
        """
        if content_type == "urlencoded" or "multipart/form-data" in content_type:
            data = BodyMutator.parse(body, content_type, keep_list=True)
            
            # 重複させる値の生成
            # multipart の場合、既存の値からメタデータをコピーするか検討
            new_item = new_val
            if "multipart" in content_type and key_to_dup in data:
                orig_v = data[key_to_dup]
                sample = orig_v[0] if isinstance(orig_v, list) else orig_v
                if isinstance(sample, dict):
                    new_item = copy.deepcopy(sample)
                    new_item["value"] = new_val

            if key_to_dup in data:
                if isinstance(data[key_to_dup], list):
                    data[key_to_dup].append(new_item)
                else:
                    data[key_to_dup] = [data[key_to_dup], new_item]
            else:
                data[key_to_dup] = [new_item]
            return BodyMutator.serialize(data, content_type)
        
        elif content_type == "json":
            try:
                data = json.loads(body)
                if key_to_dup in data:
                    orig = data[key_to_dup]
                    if isinstance(orig, list):
                        data[key_to_dup] = orig + [new_val]
                    else:
                        data[key_to_dup] = [orig, new_val]
                else:
                    data[key_to_dup] = new_val
                return json.dumps(data)
            except json.JSONDecodeError:
                return body
        
        return body

    @staticmethod
    def to_graphql_variables(body: str, content_type: str) -> Optional[Dict[str, Any]]:
        """
        Body (JSON/urlencoded) から抽出したキー値を GraphQL Variables 形式に変換。
        """
        data = BodyMutator.parse(body, content_type)
        if not data:
            return None
        return {"variables": data}
